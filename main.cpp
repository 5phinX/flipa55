#include <furi.h>
#include <furi_hal_random.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_hid.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <gui/modules/loading.h>
#include <gui/modules/variable_item_list.h>
#include <lib/lfrfid/lfrfid_worker.h>
#include <lib/toolbox/protocols/protocol_dict.h>
#include <lib/lfrfid/protocols/lfrfid_protocols.h>
#include <gui/modules/text_input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <flipper_format/flipper_format.h>
#include <toolbox/path.h>
#include <string.h>

#include "sha2.h"
#include "aes-cfb128.h"

#define FLIPA55_SETTINGS_PATH "/ext/flipa55/.settings"
#define BADUSB_LAYOUTS_DIR    "/ext/badusb/assets/layouts"
#define DEFAULT_LAYOUT_PATH   "/ext/badusb/assets/layouts/en-US.kl"

static const uint32_t key_delay_values[] = {10, 20, 30, 50, 100};
static const char* const key_delay_labels[] = {"10 ms", "20 ms", "30 ms", "50 ms", "100 ms"};
#define KEY_DELAY_COUNT (sizeof(key_delay_values) / sizeof(key_delay_values[0]))

#define PWD_MIN_LEN 4
#define PWD_MAX_LEN 64
#define PWD_LEN_COUNT (PWD_MAX_LEN - PWD_MIN_LEN + 1)
#define PWD_DEFAULT_LEN 16

typedef enum {
  PwdStructComplex = 0,
  PwdStructNumbers = 1,
  PwdStructAlphanumeric = 2,
  PwdStructCount = 3,
} PasswordStructure;

static const char* const pwd_struct_labels[] = {
  "Complex",
  "Numbers",
  "Alphanumeric",
};

// Identifiers for different views of the app
typedef enum {
  ViewInitmenu,
  ViewWidget,
  ViewManageMenu,
  ViewTextInput,
  ViewStatusWidget,
  ViewTypeMenu,
  ViewSettings,
  ViewPasswordMenu,
  ViewLoading,
} ViewId;

// Identifiers for each menu item of the init menu
typedef enum {
  MenuScanRFID,
  MenuCreateRFID,
  MenuSettings,
  MenuCreateFile,
  MenuOpenFile,
  MenuCopyFile,
  MenuEditFile,
  MenuRemoveFile,
  MenuBatchEncrypt,
  MenuTypeUsername,
  MenuTypePassword,
} MenuIndex;

// Application state
typedef struct {
  ViewDispatcher* view_dispatcher;
  Submenu* initmenu;
  Submenu* managemenu;
  Submenu* typemenu;
  VariableItemList* settings_list;
  VariableItem* layout_item;
  VariableItem* delay_item;
  VariableItemList* password_menu;
  VariableItem* pwd_len_item;
  VariableItem* pwd_struct_item;
  Widget* widget;
  Widget* status_widget;
  Loading* loading;
  TextInput* text_input;
  ViewId current_view;

  // RFID state
  LFRFIDWorker* rfid_worker;
  ProtocolDict* rfid_dict;
  ProtocolId scanned_protocol;

  uint8_t random_data[5];
  uint8_t key[32];

  FuriString* file_path;
  FuriString* layout_path;
  FuriString* layout_name;

  uint16_t layout[128];
  uint32_t key_delay_ms;

  uint8_t pwd_gen_length;
  PasswordStructure pwd_gen_struct;
  char pwd_len_str[8];

  char new_file_name[32];
  char username[128];
  char password[127];
  bool is_editing_file;
  uint32_t batch_failed_count;
  char status_msg[96];

  FuriHalUsbInterface* usb_mode_prev;
} AppState;

static void save_new_file(AppState* app);
static void copy_selected_file(AppState* app);
static void remove_selected_file(AppState* app);
static void batch_encrypt_files(AppState* app);
static bool load_username_from_file(AppState* app);
static void decrypt_selected_file(AppState* app);

static bool load_keyboard_layout(AppState* app, const char* path) {
  memcpy(app->layout, hid_asciimap, sizeof(hid_asciimap));
  bool loaded = false;

  if ( path != NULL && path[0] != '\0' ) {
    Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if ( storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING) ) {
      if ( storage_file_size(file) == sizeof(app->layout) ) {
        if ( storage_file_read(file, app->layout, sizeof(app->layout)) == sizeof(app->layout) ) {
          loaded = true;
        } else {
          memcpy(app->layout, hid_asciimap, sizeof(hid_asciimap));
        }
      }
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
  }

  if ( loaded ) {
    furi_string_set_str(app->layout_path, path);
    path_extract_filename(app->layout_path, app->layout_name, true);
  } else {
    furi_string_set_str(app->layout_path, DEFAULT_LAYOUT_PATH);
    furi_string_set_str(app->layout_name, "en-US");
  }

  if ( app->layout_item != NULL ) {
    variable_item_set_current_value_text(app->layout_item, furi_string_get_cstr(app->layout_name));
  }

  return loaded;
}

static void save_settings(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  storage_simply_mkdir(storage, "/ext/flipa55");

  FlipperFormat* ff = flipper_format_file_alloc(storage);
  if ( flipper_format_file_open_always(ff, FLIPA55_SETTINGS_PATH) ) {
    flipper_format_write_header_cstr(ff, "Flipa55 Settings", 1);
    flipper_format_write_string(ff, "Layout", app->layout_path);
    flipper_format_write_uint32(ff, "KeyDelay", &app->key_delay_ms, 1);
  }
  flipper_format_file_close(ff);
  flipper_format_free(ff);
  furi_record_close(RECORD_STORAGE);
}

static void load_settings(AppState* app) {
  furi_string_set_str(app->layout_path, DEFAULT_LAYOUT_PATH);
  app->key_delay_ms = 20;

  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  FlipperFormat* ff = flipper_format_file_alloc(storage);
  FuriString* header = furi_string_alloc();
  uint32_t version = 0;

  if ( flipper_format_file_open_existing(ff, FLIPA55_SETTINGS_PATH) ) {
    if ( flipper_format_read_header(ff, header, &version) &&
         furi_string_cmp_str(header, "Flipa55 Settings") == 0 &&
         version == 1 ) {
      flipper_format_read_string(ff, "Layout", app->layout_path);
      flipper_format_read_uint32(ff, "KeyDelay", &app->key_delay_ms, 1);
    }
  }

  furi_string_free(header);
  flipper_format_file_close(ff);
  flipper_format_free(ff);
  furi_record_close(RECORD_STORAGE);

  load_keyboard_layout(app, furi_string_get_cstr(app->layout_path));

  uint8_t delay_idx = 1; // Default 20 ms
  for ( uint8_t i = 0; i < KEY_DELAY_COUNT; i++ ) {
    if ( key_delay_values[i] == app->key_delay_ms ) {
      delay_idx = i;
      break;
    }
  }
  app->key_delay_ms = key_delay_values[delay_idx];
  if ( app->delay_item != NULL ) {
    variable_item_set_current_value_index(app->delay_item, delay_idx);
    variable_item_set_current_value_text(app->delay_item, key_delay_labels[delay_idx]);
  }
}

static void delay_change_callback(VariableItem* item) {
  AppState* app = (AppState*)variable_item_get_context(item);
  uint8_t index = variable_item_get_current_value_index(item);
  if ( index >= KEY_DELAY_COUNT ) {
    index = 0;
  }
  app->key_delay_ms = key_delay_values[index];
  variable_item_set_current_value_text(item, key_delay_labels[index]);
}

static void settings_enter_callback(void* context, uint32_t index) {
  AppState* app = (AppState*)context;
  if ( index == 0 ) {
    view_dispatcher_send_custom_event(app->view_dispatcher, 400);
  }
}

static void pwd_len_change_callback(VariableItem* item) {
  AppState* app = (AppState*)variable_item_get_context(item);
  uint8_t index = variable_item_get_current_value_index(item);
  if ( index >= PWD_LEN_COUNT ) {
    index = 0;
  }
  app->pwd_gen_length = PWD_MIN_LEN + index;
  snprintf(app->pwd_len_str, sizeof(app->pwd_len_str), "%u", app->pwd_gen_length);
  variable_item_set_current_value_text(item, app->pwd_len_str);
}

static void pwd_struct_change_callback(VariableItem* item) {
  AppState* app = (AppState*)variable_item_get_context(item);
  uint8_t index = variable_item_get_current_value_index(item);
  if ( index >= PwdStructCount ) {
    index = 0;
  }
  app->pwd_gen_struct = (PasswordStructure)index;
  variable_item_set_current_value_text(item, pwd_struct_labels[index]);
}

static void password_menu_enter_callback(void* context, uint32_t index) {
  AppState* app = (AppState*)context;
  if ( index == 0 ) {
    // "Enter password"
    view_dispatcher_send_custom_event(app->view_dispatcher, 309);
  } else if ( index == 2 ) {
    // Also allow OK button to cycle password structure
    uint8_t next = ((uint8_t)app->pwd_gen_struct + 1) % PwdStructCount;
    app->pwd_gen_struct = (PasswordStructure)next;
    variable_item_set_current_value_index(app->pwd_struct_item, next);
    variable_item_set_current_value_text(app->pwd_struct_item, pwd_struct_labels[next]);
  } else if ( index == 3 ) {
    // "Generate password"
    view_dispatcher_send_custom_event(app->view_dispatcher, 310);
  }
}

static void generate_random_password(AppState* app) {
  static const char charset_lower[] = "abcdefghijklmnopqrstuvwxyz";
  static const char charset_upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const char charset_digits[] = "0123456789";
  static const char charset_symbols[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  static const char charset_alnum[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  static const char charset_complex[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

  uint8_t len = app->pwd_gen_length;
  if ( len < PWD_MIN_LEN ) len = PWD_MIN_LEN;
  if ( len >= sizeof(app->password) ) len = sizeof(app->password) - 1;

  memset(app->password, 0, sizeof(app->password));
  uint8_t pos = 0;

  if ( app->pwd_gen_struct == PwdStructNumbers ) {
    for ( uint8_t i = 0; i < len; i++ ) {
      app->password[i] = charset_digits[furi_hal_random_get() % (sizeof(charset_digits) - 1)];
    }
  } else if ( app->pwd_gen_struct == PwdStructAlphanumeric ) {
    // Guarantee at least one lowercase, one uppercase, and one digit
    app->password[pos++] = charset_lower[furi_hal_random_get() % (sizeof(charset_lower) - 1)];
    app->password[pos++] = charset_upper[furi_hal_random_get() % (sizeof(charset_upper) - 1)];
    app->password[pos++] = charset_digits[furi_hal_random_get() % (sizeof(charset_digits) - 1)];
    while ( pos < len ) {
      app->password[pos++] = charset_alnum[furi_hal_random_get() % (sizeof(charset_alnum) - 1)];
    }
  } else {
    // PwdStructComplex: guarantee at least one lowercase, uppercase, digit, and symbol
    app->password[pos++] = charset_lower[furi_hal_random_get() % (sizeof(charset_lower) - 1)];
    app->password[pos++] = charset_upper[furi_hal_random_get() % (sizeof(charset_upper) - 1)];
    app->password[pos++] = charset_digits[furi_hal_random_get() % (sizeof(charset_digits) - 1)];
    app->password[pos++] = charset_symbols[furi_hal_random_get() % (sizeof(charset_symbols) - 1)];
    while ( pos < len ) {
      app->password[pos++] = charset_complex[furi_hal_random_get() % (sizeof(charset_complex) - 1)];
    }
  }

  // Fisher-Yates shuffle so required character classes appear at random positions
  for ( uint8_t i = len - 1; i > 0; i-- ) {
    uint8_t j = furi_hal_random_get() % (i + 1);
    char tmp = app->password[i];
    app->password[i] = app->password[j];
    app->password[j] = tmp;
  }
  app->password[len] = '\0';
}

static void hid_type_string(AppState* app, const char* text) {
  if ( text[0] == '\0' ) {
    view_dispatcher_send_custom_event(app->view_dispatcher, 308);
    return;
  }

  if ( furi_hal_usb_get_config() != &usb_hid ) {
    app->usb_mode_prev = furi_hal_usb_get_config();
    furi_hal_usb_unlock();
    if ( !furi_hal_usb_set_config(&usb_hid, NULL) ) {
      view_dispatcher_send_custom_event(app->view_dispatcher, 304);
      return;
    }
  }

  // Wait for host USB HID enumeration (up to ~2 seconds)
  uint32_t timeout = 200;
  while ( !furi_hal_hid_is_connected() && timeout > 0 ) {
    furi_delay_ms(10);
    timeout--;
  }

  if ( !furi_hal_hid_is_connected() ) {
    view_dispatcher_send_custom_event(app->view_dispatcher, 305);
    return;
  }

  for ( size_t i = 0; text[i] != '\0'; i++ ) {
    uint8_t ch = (uint8_t)text[i];
    uint16_t keycode = (ch < 128) ? app->layout[ch] : HID_KEYBOARD_NONE;
    if ( keycode == HID_KEYBOARD_NONE ) {
      furi_hal_hid_kb_release_all();
      view_dispatcher_send_custom_event(app->view_dispatcher, 306);
      return;
    }
    if ( !furi_hal_hid_kb_press(keycode) ) {
      furi_hal_hid_kb_release_all();
      view_dispatcher_send_custom_event(app->view_dispatcher, 307);
      return;
    }
    furi_delay_ms(app->key_delay_ms);
    if ( !furi_hal_hid_kb_release(keycode) ) {
      furi_hal_hid_kb_release_all();
      view_dispatcher_send_custom_event(app->view_dispatcher, 307);
      return;
    }
    furi_delay_ms(app->key_delay_ms);
  }
  furi_hal_hid_kb_release_all();
}

static void generate_random_em4100_data(AppState* app) {
  furi_hal_random_fill_buf(app->random_data, 5);
}

// Callback for menu item activated by OK button
static void menu_callback(void* context, uint32_t index) {
  ViewDispatcher* view_dispatcher = (ViewDispatcher*)context;
  view_dispatcher_send_custom_event(view_dispatcher, index);
}

// RFID scan callback
static void rfid_read_callback(LFRFIDWorkerReadResult read_result, ProtocolId protocol, void* context) {
  if ( read_result == LFRFIDWorkerReadDone ) {
    AppState* app = (AppState*)context;

    // Store the scanned protocol
    app->scanned_protocol = protocol;

    FuriString* parsed_data = furi_string_alloc();

    protocol_dict_render_data(app->rfid_dict, parsed_data, protocol);

    sha256_initialize();
    sha256_addData( (unsigned const char*)furi_string_get_cstr(parsed_data), furi_string_size(parsed_data) );
    sha256_finalize(app->key);

    furi_string_reset(parsed_data);
    for ( size_t i = 0; i < sizeof(app->key); i++ ) {
      furi_string_cat_printf(parsed_data, "%02X", app->key[i]);
    }
    FURI_LOG_I("Flipa55", "Key: %s", furi_string_get_cstr(parsed_data));

    furi_string_free(parsed_data);

    view_dispatcher_send_custom_event(app->view_dispatcher, 200);

  }
}

// RFID write callback
static void rfid_write_callback(LFRFIDWorkerWriteResult result, void* context) {
  AppState* app = (AppState*)context;
  if ( result == LFRFIDWorkerWriteOK ) {
    view_dispatcher_send_custom_event(app->view_dispatcher, 100);
  } else {
    view_dispatcher_send_custom_event(app->view_dispatcher, 101);
  }
}

// Validator to reject empty or already existing file names in /ext/flipa55/data
static bool file_name_validator(const char* text, FuriString* error, void* context) {
  (void)context;
  if ( text == NULL || text[0] == '\0' ) {
    furi_string_set_str(error, "File name\ncannot be\nempty!");
    return false;
  }

  FuriString* check_path = furi_string_alloc();
  furi_string_printf(check_path, "/ext/flipa55/data/%s", text);

  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  bool exists = storage_common_exists(storage, furi_string_get_cstr(check_path));
  furi_record_close(RECORD_STORAGE);
  furi_string_free(check_path);

  if ( exists ) {
    furi_string_set_str(error, "File already\nexists!");
    return false;
  }

  return true;
}

// File name text entry callback
static void file_name_input_callback(void* context){
  AppState* app = (AppState*)context;

  view_dispatcher_send_custom_event(app->view_dispatcher, 300);
}

// Copy destination file name text entry callback
static void copy_file_name_input_callback(void* context){
  AppState* app = (AppState*)context;

  copy_selected_file(app);
}

// Username input callback
static void username_input_callback(void* context){
  AppState* app = (AppState*)context;

  view_dispatcher_send_custom_event(app->view_dispatcher, 301);
}

// Password text entry callback
static void password_input_callback(void* context){
  AppState* app = (AppState*)context;

  save_new_file(app);
}

// Save new file
static void save_new_file(AppState *app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  // Cipher data
  unsigned char ciphertext[144];
  unsigned char plaintext[144];
  unsigned int cipherBlocks;

  // File open status
  bool file_op_success = false;
  bool file_exists = false;

  // Set loading view
  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  // Create a directory /ext/flipa55/data if it does not exist
  storage_simply_mkdir(storage, "/ext/flipa55");
  storage_simply_mkdir(storage, "/ext/flipa55/data");

  if ( !app->is_editing_file ) {
    furi_string_printf(app->file_path, "/ext/flipa55/data/%s", app->new_file_name);
  }

  File* fout = storage_file_alloc(storage);
  if ( !app->is_editing_file && storage_common_exists(storage, furi_string_get_cstr(app->file_path)) ) {
    file_exists = true;
  } else if ( storage_file_open(
                  fout,
                  furi_string_get_cstr(app->file_path),
                  FSAM_WRITE,
                  app->is_editing_file ? FSOM_CREATE_ALWAYS : FSOM_CREATE_NEW) ) {
    // Generate IV
    furi_hal_random_fill_buf(plaintext, 16);

    // Prepare plaintext
    plaintext[16] = strlen(app->password);
    strcpy((char*)&plaintext[17], app->password);
    if ( ((plaintext[16]+1) % 16) == 0 ) cipherBlocks = (plaintext[16]+1) / 16;
    else cipherBlocks = ((plaintext[16]+1) / 16) + 1;

    // Encrypt file contents
    encrypt_cfb128(app->key, plaintext, ciphertext, cipherBlocks, 256);

    // Write username in plaintext
    storage_file_write(fout, app->username, strlen(app->username));
    storage_file_write(fout, "\n", 1);
    storage_file_write(fout, ciphertext, (cipherBlocks+1)*16);

    file_op_success = true;
  } else {
    file_op_success = false;
  }

  storage_file_close(fout);
  storage_file_free(fout);
  furi_record_close(RECORD_STORAGE);

  if ( file_exists ) view_dispatcher_send_custom_event(app->view_dispatcher, 311);
  else if ( file_op_success == true ) view_dispatcher_send_custom_event(app->view_dispatcher, 302);
  else view_dispatcher_send_custom_event(app->view_dispatcher, 303);
}

// Copy selected file to a new file name in /ext/flipa55/data
static void copy_selected_file(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  bool file_op_success = false;
  bool file_exists = false;

  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  storage_simply_mkdir(storage, "/ext/flipa55");
  storage_simply_mkdir(storage, "/ext/flipa55/data");

  FuriString* dest_path = furi_string_alloc();
  furi_string_printf(dest_path, "/ext/flipa55/data/%s", app->new_file_name);

  if ( storage_common_exists(storage, furi_string_get_cstr(dest_path)) ) {
    file_exists = true;
  } else if ( storage_common_copy(storage, furi_string_get_cstr(app->file_path), furi_string_get_cstr(dest_path)) == FSE_OK ) {
    file_op_success = true;
  }

  furi_string_free(dest_path);
  furi_record_close(RECORD_STORAGE);

  if ( file_exists ) view_dispatcher_send_custom_event(app->view_dispatcher, 311);
  else if ( file_op_success ) view_dispatcher_send_custom_event(app->view_dispatcher, 312);
  else view_dispatcher_send_custom_event(app->view_dispatcher, 303);
}

// Remove selected file from /ext/flipa55/data
static void remove_selected_file(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  bool file_op_success = false;

  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  if ( storage_common_remove(storage, furi_string_get_cstr(app->file_path)) == FSE_OK ) {
    file_op_success = true;
  }

  furi_record_close(RECORD_STORAGE);

  if ( file_op_success ) view_dispatcher_send_custom_event(app->view_dispatcher, 313);
  else view_dispatcher_send_custom_event(app->view_dispatcher, 303);
}

// Batch encrypt all plaintext files in /ext/flipa55/plain into /ext/flipa55/data
static void batch_encrypt_files(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  unsigned char ciphertext[144];
  unsigned char plaintext[144];
  unsigned int cipherBlocks;

  app->batch_failed_count = 0;

  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  storage_simply_mkdir(storage, "/ext/flipa55");
  storage_simply_mkdir(storage, "/ext/flipa55/data");

  File* dir = storage_file_alloc(storage);
  if ( !storage_dir_open(dir, "/ext/flipa55/plain") ) {
    storage_dir_close(dir);
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
    view_dispatcher_send_custom_event(app->view_dispatcher, 303);
    return;
  }

  FileInfo fileinfo;
  char entry_name[64];
  FuriString* src_path = furi_string_alloc();
  FuriString* dst_path = furi_string_alloc();

  while ( storage_dir_read(dir, &fileinfo, entry_name, sizeof(entry_name)) ) {
    if ( file_info_is_dir(&fileinfo) || entry_name[0] == '.' ) {
      continue;
    }

    furi_string_printf(src_path, "/ext/flipa55/plain/%s", entry_name);
    furi_string_printf(dst_path, "/ext/flipa55/data/%s", entry_name);

    // Skip already existing files in /ext/flipa55/data
    if ( storage_common_exists(storage, furi_string_get_cstr(dst_path)) ) {
      app->batch_failed_count++;
      continue;
    }

    bool read_ok = false;
    memset(app->username, 0, sizeof(app->username));
    memset(app->password, 0, sizeof(app->password));

    File* fin = storage_file_alloc(storage);
    if ( storage_file_open(fin, furi_string_get_cstr(src_path), FSAM_READ, FSOM_OPEN_EXISTING) ) {
      if ( storage_file_size(fin) != 0 ) {
        size_t u_len = 0;
        char ch = 0;
        bool found_newline = false;
        while ( storage_file_read(fin, &ch, 1) == 1 ) {
          if ( ch == '\n' ) {
            found_newline = true;
            break;
          }
          if ( ch != '\r' && u_len < sizeof(app->username) - 1 ) {
            app->username[u_len++] = ch;
          }
        }
        app->username[u_len] = '\0';

        if ( found_newline && u_len > 0 ) {
          size_t p_len = 0;
          while ( storage_file_read(fin, &ch, 1) == 1 ) {
            if ( ch == '\n' ) {
              break;
            }
            if ( ch != '\r' && p_len < sizeof(app->password) - 1 ) {
              app->password[p_len++] = ch;
            }
          }
          app->password[p_len] = '\0';
          if ( p_len > 0 ) {
            read_ok = true;
          }
        }
      }
    }
    storage_file_close(fin);
    storage_file_free(fin);

    if ( !read_ok ) {
      app->batch_failed_count++;
      continue;
    }

    File* fout = storage_file_alloc(storage);
    if ( storage_file_open(fout, furi_string_get_cstr(dst_path), FSAM_WRITE, FSOM_CREATE_NEW) ) {
      furi_hal_random_fill_buf(plaintext, 16);

      plaintext[16] = strlen(app->password);
      strcpy((char*)&plaintext[17], app->password);
      if ( ((plaintext[16] + 1) % 16) == 0 ) cipherBlocks = (plaintext[16] + 1) / 16;
      else cipherBlocks = ((plaintext[16] + 1) / 16) + 1;

      encrypt_cfb128(app->key, plaintext, ciphertext, cipherBlocks, 256);

      size_t u_bytes = strlen(app->username);
      size_t c_bytes = (cipherBlocks + 1) * 16;
      if ( storage_file_write(fout, app->username, u_bytes) != u_bytes ||
           storage_file_write(fout, "\n", 1) != 1 ||
           storage_file_write(fout, ciphertext, c_bytes) != c_bytes ) {
        app->batch_failed_count++;
      }
    } else {
      app->batch_failed_count++;
    }
    storage_file_close(fout);
    storage_file_free(fout);
  }

  furi_string_free(src_path);
  furi_string_free(dst_path);
  storage_dir_close(dir);
  storage_file_free(dir);
  furi_record_close(RECORD_STORAGE);

  view_dispatcher_send_custom_event(app->view_dispatcher, 314);
}

// Read only the plaintext username line from the selected file without decrypting
static bool load_username_from_file(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  bool file_op_success = false;

  memset(app->username, 0, sizeof(app->username));

  File* fin = storage_file_alloc(storage);
  if ( storage_file_open(fin, furi_string_get_cstr(app->file_path), FSAM_READ, FSOM_OPEN_EXISTING) ) {
    if ( storage_file_size(fin) != 0 ) {
      size_t i = 0;
      char ch = 0;
      while ( i < sizeof(app->username) - 1 && storage_file_read(fin, &ch, 1) == 1 ) {
        if ( ch == '\n' ) {
          break;
        }
        app->username[i++] = ch;
      }
      app->username[i] = '\0';
      file_op_success = true;
    }
  }

  storage_file_close(fin);
  storage_file_free(fin);
  furi_record_close(RECORD_STORAGE);

  return file_op_success;
}

// Decrypt selected file and load data into the app state
static void decrypt_selected_file(AppState* app) {
  Storage* storage = (Storage*)furi_record_open(RECORD_STORAGE);
  // Cipher data
  unsigned char ciphertext[144];
  unsigned char plaintext[144];
  unsigned int cipherBlocks;
  int i;

  // File open status
  bool file_op_success = false;

  // Set loading view
  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  File* fin = storage_file_alloc(storage);
  if ( storage_file_open(fin, furi_string_get_cstr(app->file_path), FSAM_READ, FSOM_OPEN_EXISTING) ) {
    if ( storage_file_size(fin) != 0 ) {
      i = 0;
      do {
        storage_file_read(fin, &(app->username[i]), 1);
        i++;
      } while ( app->username[i-1] != '\n' );
      app->username[i-1] = 0;
      cipherBlocks = storage_file_read(fin, ciphertext, 144);
      cipherBlocks = cipherBlocks/16;

      decrypt_cfb128(app->key, ciphertext, plaintext, cipherBlocks-1, 256);

      memset(app->password, 0, sizeof(app->password));
      strncpy( app->password, (const char*)&plaintext[1], plaintext[0] );

      file_op_success = true;
    } else {
      file_op_success = false;
    }
  } else {
    file_op_success = false;
  }

  storage_file_close(fin);
  storage_file_free(fin);
  furi_record_close(RECORD_STORAGE);

  if ( file_op_success == false ) view_dispatcher_send_custom_event(app->view_dispatcher, 303);
  else {
    if ( furi_hal_usb_get_config() != &usb_hid ) {
      app->usb_mode_prev = furi_hal_usb_get_config();
      furi_hal_usb_unlock();
      furi_hal_usb_set_config(&usb_hid, NULL);
    }

    submenu_reset(app->typemenu);
    submenu_add_item(app->typemenu, app->username, MenuTypeUsername, menu_callback, app->view_dispatcher);
    submenu_add_item(app->typemenu, "Type password", MenuTypePassword, menu_callback, app->view_dispatcher);

    app->current_view = ViewTypeMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewTypeMenu);
  }
}

// Custom event processing
static bool custom_event_callback(void* context, uint32_t event) {
  AppState* app = (AppState*)context;

  DialogsApp* dialogs;
  bool success;

  // Just log the selected item for now
  FURI_LOG_I("Flipa55", "Menu item %lu selected", event);

  switch(event) {
    case MenuScanRFID:
      widget_reset(app->widget);
      widget_add_text_box_element(app->widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "Scanning RFID...", true);
      app->current_view = ViewWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);
      // Start the RFID worker
      lfrfid_worker_start_thread(app->rfid_worker);
      lfrfid_worker_read_start(app->rfid_worker, LFRFIDWorkerReadTypeAuto, rfid_read_callback, app);
      return true;
      break;

    case MenuCreateRFID:
      generate_random_em4100_data(app);

      widget_reset(app->widget);
      widget_add_text_box_element(app->widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "Writing tag...", true);
      app->current_view = ViewWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);

      protocol_dict_set_data(app->rfid_dict, LFRFIDProtocolEM4100, app->random_data, 5);

      lfrfid_worker_start_thread(app->rfid_worker);
      lfrfid_worker_write_start(app->rfid_worker, LFRFIDProtocolEM4100, rfid_write_callback, app);
      return true;
      break;

    case MenuSettings:
      app->current_view = ViewSettings;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewSettings);
      return true;
      break;

    case MenuOpenFile:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions browser_options;

      dialog_file_browser_set_basic_options(&browser_options, "*", NULL);

      furi_string_set_str(app->file_path, "/ext/flipa55/data");

      success = dialog_file_browser_show(dialogs, app->file_path, app->file_path, &browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        decrypt_selected_file(app);
      }
      return true;
      break;

    case MenuCreateFile:
      app->is_editing_file = false;
      memset(app->new_file_name, 0, sizeof(app->new_file_name));
      text_input_reset(app->text_input);
      text_input_set_header_text(app->text_input, "Enter file name:");
      text_input_set_validator(app->text_input, file_name_validator, app);
      text_input_set_result_callback(app->text_input, file_name_input_callback, app, app->new_file_name, sizeof(app->new_file_name), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
      return true;
      break;

    case MenuCopyFile:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions copy_browser_options;

      dialog_file_browser_set_basic_options(&copy_browser_options, "*", NULL);

      furi_string_set_str(app->file_path, "/ext/flipa55/data");

      success = dialog_file_browser_show(dialogs, app->file_path, app->file_path, &copy_browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        memset(app->new_file_name, 0, sizeof(app->new_file_name));
        text_input_reset(app->text_input);
        text_input_set_header_text(app->text_input, "Enter new file name:");
        text_input_set_validator(app->text_input, file_name_validator, app);
        text_input_set_result_callback(app->text_input, copy_file_name_input_callback, app, app->new_file_name, sizeof(app->new_file_name), true);

        app->current_view = ViewTextInput;
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
      }
      return true;
      break;

    case MenuEditFile:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions edit_browser_options;

      dialog_file_browser_set_basic_options(&edit_browser_options, "*", NULL);

      furi_string_set_str(app->file_path, "/ext/flipa55/data");

      success = dialog_file_browser_show(dialogs, app->file_path, app->file_path, &edit_browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        app->is_editing_file = true;
        if ( load_username_from_file(app) ) {
          text_input_reset(app->text_input);
          text_input_set_validator(app->text_input, NULL, NULL);
          text_input_set_header_text(app->text_input, "Enter username:");
          text_input_set_result_callback(app->text_input, username_input_callback, app, app->username, sizeof(app->username), false);

          app->current_view = ViewTextInput;
          view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
        } else {
          view_dispatcher_send_custom_event(app->view_dispatcher, 303);
        }
      }
      return true;
      break;

    case MenuRemoveFile:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions remove_browser_options;

      dialog_file_browser_set_basic_options(&remove_browser_options, "*", NULL);

      furi_string_set_str(app->file_path, "/ext/flipa55/data");

      success = dialog_file_browser_show(dialogs, app->file_path, app->file_path, &remove_browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        remove_selected_file(app);
      }
      return true;
      break;

    case MenuBatchEncrypt:
      batch_encrypt_files(app);
      return true;
      break;

    case MenuTypeUsername:
      hid_type_string(app, app->username);
      return true;
      break;

    case MenuTypePassword:
      hid_type_string(app, app->password);
      return true;
      break;

    // Custom code for return to main menu
    case 100:
      // Stop the worker and open the management menu
      lfrfid_worker_stop(app->rfid_worker);
      lfrfid_worker_stop_thread(app->rfid_worker);

      app->current_view = ViewInitmenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewInitmenu);
      return true;
      break;

    case 101:
      widget_reset(app->widget);
      widget_add_text_box_element(app->widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "RFID tag write error.\n\nPress back to return to menu.", true);
      return true;
      break;

    // Custom code for management menu
    case 200:
      lfrfid_worker_stop(app->rfid_worker);
      lfrfid_worker_stop_thread(app->rfid_worker);
      app->current_view = ViewManageMenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewManageMenu);
      return true;
      break;

    // Custom code for management menu
    case 201:
      if ( furi_hal_usb_get_config() == &usb_hid && app->usb_mode_prev != NULL ) {
        furi_hal_usb_set_config(app->usb_mode_prev, NULL);
      }
      app->current_view = ViewManageMenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewManageMenu);
      return true;
      break;

    // File name has been entered
    case 300:
      memset(app->username, 0, sizeof(app->username));
      text_input_reset(app->text_input);
      text_input_set_validator(app->text_input, NULL, NULL);
      text_input_set_header_text(app->text_input, "Enter username:");
      text_input_set_result_callback(app->text_input, username_input_callback, app, app->username, sizeof(app->username), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
      return true;
      break;

    // Username has been entered
    case 301:
      variable_item_list_set_selected_item(app->password_menu, 0);
      app->current_view = ViewPasswordMenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewPasswordMenu);
      return true;
      break;

    // Manual password entry selected from password submenu
    case 309:
      memset(app->password, 0, sizeof(app->password));
      text_input_reset(app->text_input);
      text_input_set_validator(app->text_input, NULL, NULL);
      text_input_set_header_text(app->text_input, "Enter password:");
      text_input_set_result_callback(app->text_input, password_input_callback, app, app->password, sizeof(app->password), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
      return true;
      break;

    // Generate random password and save file
    case 310:
      generate_random_password(app);
      save_new_file(app);
      return true;
      break;

    // File already exists
    case 311:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "File already exists\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // File copy succeeded
    case 312:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "File copied\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // File remove succeeded
    case 313:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "File removed\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // Batch encryption finished
    case 314:
      snprintf(
          app->status_msg,
          sizeof(app->status_msg),
          "Batch encrypt done\nFailed: %lu\nPress back to return.",
          (unsigned long)app->batch_failed_count);
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, app->status_msg, true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // File operation succeeded
    case 302:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "File written\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // File operation failed
    case 303:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "File IO error\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // HID error: USB config switch failed
    case 304:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "USB config error\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // HID error: Host USB HID not connected
    case 305:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "USB not connected\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // HID error: Unsupported character in string
    case 306:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "Unsupported char\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // HID error: Failed to send key report
    case 307:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "HID key send error\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // HID error: Empty string
    case 308:
      widget_reset(app->status_widget);
      widget_add_text_box_element(app->status_widget, 0, 0, 128, 64, AlignCenter, AlignCenter, "Empty string\nPress back to return to menu.", true);

      app->current_view = ViewStatusWidget;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewStatusWidget);
      return true;
      break;

    // Open keyboard layout file browser
    case 400:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions layout_browser_options;

      dialog_file_browser_set_basic_options(&layout_browser_options, ".kl", NULL);
      layout_browser_options.base_path = BADUSB_LAYOUTS_DIR;

      if ( furi_string_empty(app->layout_path) ) {
        furi_string_set_str(app->layout_path, BADUSB_LAYOUTS_DIR);
      }

      success = dialog_file_browser_show(dialogs, app->layout_path, app->layout_path, &layout_browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        load_keyboard_layout(app, furi_string_get_cstr(app->layout_path));
      }
      return true;
      break;
  }

  return true;
}

// Callback for the back button
static bool navigation_event_callback(void* context) {
  AppState* app = (AppState*)context;

  switch ( app->current_view ) {
    case ViewInitmenu:
      // Stop the dispatcher loop, which will end the application
      view_dispatcher_stop(app->view_dispatcher);
      break;
    case ViewWidget:
    case ViewManageMenu:
      view_dispatcher_send_custom_event(app->view_dispatcher, 100);
      break;
    case ViewTextInput:
    case ViewStatusWidget:
    case ViewTypeMenu:
    case ViewPasswordMenu:
      view_dispatcher_send_custom_event(app->view_dispatcher, 201);
      break;
    case ViewSettings:
      save_settings(app);
      app->current_view = ViewInitmenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewInitmenu);
      break;
    case ViewLoading:
      // Ignore back button while waiting
      break;
  }

  return true;
}

extern "C" int32_t flipa55_main() {
  // Create app state
  AppState* app = (AppState*)malloc(sizeof(AppState));
  app->view_dispatcher = view_dispatcher_alloc();
  app->initmenu = submenu_alloc();
  app->managemenu = submenu_alloc();
  app->typemenu = submenu_alloc();
  app->settings_list = variable_item_list_alloc();
  app->password_menu = variable_item_list_alloc();
  app->widget = widget_alloc();
  app->status_widget = widget_alloc();
  app->loading = loading_alloc();
  app->current_view = ViewInitmenu;
  app->file_path = furi_string_alloc();
  app->layout_path = furi_string_alloc();
  app->layout_name = furi_string_alloc();
  app->text_input = text_input_alloc();
  app->is_editing_file = false;
  app->usb_mode_prev = furi_hal_usb_get_config();

  // Configure settings list
  app->layout_item = variable_item_list_add(app->settings_list, "Layout", 1, NULL, app);
  app->delay_item = variable_item_list_add(app->settings_list, "Key Delay", KEY_DELAY_COUNT, delay_change_callback, app);
  variable_item_list_set_enter_callback(app->settings_list, settings_enter_callback, app);
  load_settings(app);

  // Configure password generation menu
  app->pwd_gen_length = PWD_DEFAULT_LEN;
  app->pwd_gen_struct = PwdStructComplex;
  snprintf(app->pwd_len_str, sizeof(app->pwd_len_str), "%u", app->pwd_gen_length);

  variable_item_list_add(app->password_menu, "Enter password", 0, NULL, app);
  app->pwd_len_item = variable_item_list_add(app->password_menu, "Password length", PWD_LEN_COUNT, pwd_len_change_callback, app);
  variable_item_set_current_value_index(app->pwd_len_item, PWD_DEFAULT_LEN - PWD_MIN_LEN);
  variable_item_set_current_value_text(app->pwd_len_item, app->pwd_len_str);

  app->pwd_struct_item = variable_item_list_add(app->password_menu, "Structure", PwdStructCount, pwd_struct_change_callback, app);
  variable_item_set_current_value_index(app->pwd_struct_item, PwdStructComplex);
  variable_item_set_current_value_text(app->pwd_struct_item, pwd_struct_labels[PwdStructComplex]);

  variable_item_list_add(app->password_menu, "Generate password", 0, NULL, app);
  variable_item_list_set_enter_callback(app->password_menu, password_menu_enter_callback, app);

  // Add items to the init menu
  submenu_add_item(app->initmenu, "Scan RFID key", MenuScanRFID, menu_callback, app->view_dispatcher);
  submenu_add_item(app->initmenu, "Create RFID key", MenuCreateRFID, menu_callback, app->view_dispatcher);
  submenu_add_item(app->initmenu, "Settings", MenuSettings, menu_callback, app->view_dispatcher);

  // Register callbacks for defined events
  view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
  view_dispatcher_set_custom_event_callback(app->view_dispatcher, custom_event_callback);
  view_dispatcher_set_navigation_event_callback(app->view_dispatcher, navigation_event_callback);

  // Add items to the management menu
  submenu_add_item(app->managemenu, "New password file", MenuCreateFile, menu_callback, app->view_dispatcher);
  submenu_add_item(app->managemenu, "Open password file", MenuOpenFile, menu_callback, app->view_dispatcher);
  submenu_add_item(app->managemenu, "Copy password file", MenuCopyFile, menu_callback, app->view_dispatcher);
  submenu_add_item(app->managemenu, "Edit password file", MenuEditFile, menu_callback, app->view_dispatcher);
  submenu_add_item(app->managemenu, "Remove password file", MenuRemoveFile, menu_callback, app->view_dispatcher);
  submenu_add_item(app->managemenu, "Batch encrypt files", MenuBatchEncrypt, menu_callback, app->view_dispatcher);

  // Allocate the RFID dictionary and worker
  app->rfid_dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
  app->rfid_worker = lfrfid_worker_alloc(app->rfid_dict);

  // Add the menu to the dispatcher
  view_dispatcher_add_view(app->view_dispatcher, ViewInitmenu, submenu_get_view(app->initmenu));
  view_dispatcher_add_view(app->view_dispatcher, ViewManageMenu, submenu_get_view(app->managemenu));
  view_dispatcher_add_view(app->view_dispatcher, ViewTypeMenu, submenu_get_view(app->typemenu));
  view_dispatcher_add_view(app->view_dispatcher, ViewSettings, variable_item_list_get_view(app->settings_list));
  view_dispatcher_add_view(app->view_dispatcher, ViewPasswordMenu, variable_item_list_get_view(app->password_menu));
  // Add the widget view to the dispatcher
  view_dispatcher_add_view(app->view_dispatcher, ViewWidget, widget_get_view(app->widget));
  view_dispatcher_add_view(app->view_dispatcher, ViewStatusWidget, widget_get_view(app->status_widget));
  // Add text input to the dispatcher
  view_dispatcher_add_view(app->view_dispatcher, ViewTextInput, text_input_get_view(app->text_input));

  // Add loading view to the dispatcher
  view_dispatcher_add_view(app->view_dispatcher, ViewLoading, loading_get_view(app->loading));

  Gui* gui = (Gui*)furi_record_open(RECORD_GUI);
  view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);

  // Set the initial screen
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewInitmenu);

  // Run the view dispatcher loop
  view_dispatcher_run(app->view_dispatcher);

  // Clean up and exit
  if ( furi_hal_usb_get_config() == &usb_hid && app->usb_mode_prev != NULL ) {
    furi_hal_usb_set_config(app->usb_mode_prev, NULL);
  }
  lfrfid_worker_free(app->rfid_worker);
  protocol_dict_free(app->rfid_dict);

  view_dispatcher_remove_view(app->view_dispatcher, ViewInitmenu);
  submenu_free(app->initmenu);
  view_dispatcher_remove_view(app->view_dispatcher, ViewManageMenu);
  submenu_free(app->managemenu);
  view_dispatcher_remove_view(app->view_dispatcher, ViewTypeMenu);
  submenu_free(app->typemenu);
  view_dispatcher_remove_view(app->view_dispatcher, ViewSettings);
  variable_item_list_free(app->settings_list);
  view_dispatcher_remove_view(app->view_dispatcher, ViewPasswordMenu);
  variable_item_list_free(app->password_menu);

  view_dispatcher_remove_view(app->view_dispatcher, ViewWidget);
  widget_free(app->widget);
  view_dispatcher_remove_view(app->view_dispatcher, ViewStatusWidget);
  widget_free(app->status_widget);

  view_dispatcher_remove_view(app->view_dispatcher, ViewLoading);
  loading_free(app->loading);

  furi_string_free(app->file_path);
  furi_string_free(app->layout_path);
  furi_string_free(app->layout_name);

  view_dispatcher_remove_view(app->view_dispatcher, ViewTextInput);
  text_input_free(app->text_input);

  view_dispatcher_free(app->view_dispatcher);
  furi_record_close(RECORD_GUI);
  free(app);

  return 0;
}
