#include <furi.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <gui/modules/loading.h>
#include <lib/lfrfid/lfrfid_worker.h>
#include <lib/toolbox/protocols/protocol_dict.h>
#include <lib/lfrfid/protocols/lfrfid_protocols.h>
#include <gui/modules/text_input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <string.h>

#include "sha2.h"
#include "aes-cfb128.h"

// Identifiers for different views of the app
typedef enum {
  ViewInitmenu,
  ViewWidget,
  ViewManageMenu,
  ViewTextInput,
  ViewStatusWidget,
  ViewLoading,
} ViewId;

// Identifiers for each menu item of the init menu
typedef enum {
  MenuScanRFID,
  MenuCreateRFID,
  MenuCreateFile,
  MenuOpenFile,
  MenuCopyFile,
  MenuEditFile,
  MenuRemoveFile,
} MenuIndex;

// Application state
typedef struct {
  ViewDispatcher* view_dispatcher;
  Submenu* initmenu;
  Submenu* managemenu;
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

  char new_file_name[32];
  char username[128];
  char password[127];
} AppState;

static void save_new_file(AppState* app);
static void decrypt_selected_file(AppState* app);

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

// File name text entry callback
static void file_name_input_callback(void* context){
  AppState* app = (AppState*)context;

  view_dispatcher_send_custom_event(app->view_dispatcher, 300);
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

  // Set loading view
  app->current_view = ViewLoading;
  view_dispatcher_switch_to_view(app->view_dispatcher, ViewLoading);

  // Create a directory /ext/flipa55 if it does not exist
  storage_simply_mkdir(storage, "/ext/flipa55");

  furi_string_printf(app->file_path, "/ext/flipa55/%s", app->new_file_name);

  File* fout = storage_file_alloc(storage);
  if ( storage_file_open(fout, furi_string_get_cstr(app->file_path), FSAM_WRITE, FSOM_CREATE_ALWAYS) ) {
    // Generate IV
    furi_hal_random_fill_buf(plaintext, 16);

    // Prepare plaintext
    plaintext[16] = strlen(app->password);
    strcpy((char*)&plaintext[17], app->password);
    if ( (plaintext[16] % 16) == 0 ) cipherBlocks = plaintext[16] / 16;
    else cipherBlocks = (plaintext[16] / 16) + 1;

    // Encrypt file contents
    encrypt_cfb128(app->key, plaintext, ciphertext, cipherBlocks, 256);

    // Write username in plaintext
    storage_file_write(fout, app->username, strlen(app->username));
    storage_file_write(fout, "\n", 1);
    storage_file_write(fout, ciphertext, cipherBlocks*16);

    file_op_success = true;
  } else {
    file_op_success = false;
  }

  storage_file_close(fout);
  storage_file_free(fout);
  furi_record_close(RECORD_STORAGE);

  if ( file_op_success == true ) view_dispatcher_send_custom_event(app->view_dispatcher, 302);
  else view_dispatcher_send_custom_event(app->view_dispatcher, 303);
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

      decrypt_cfb128(app->key, ciphertext, plaintext, cipherBlocks, 256);

      memset(app->password, 0, sizeof(app->password));
      strncpy( app->password, (const char*)&ciphertext[1], ciphertext[0] );

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
    FURI_LOG_I("Flipa55", "Username: %s", app->username);
    FURI_LOG_I("Flipa55", "Password: %s", app->password);
    view_dispatcher_send_custom_event(app->view_dispatcher, 200);
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

    case MenuOpenFile:
      dialogs = (DialogsApp*)furi_record_open(RECORD_DIALOGS);
      DialogsFileBrowserOptions browser_options;

      dialog_file_browser_set_basic_options(&browser_options, "*", NULL);

      furi_string_set_str(app->file_path, "/ext/flipa55");

      success = dialog_file_browser_show(dialogs, app->file_path, app->file_path, &browser_options);

      furi_record_close(RECORD_DIALOGS);

      if ( success ) {
        decrypt_selected_file(app);
      }
      return true;
      break;

    case MenuCreateFile:
      memset(app->new_file_name, 0, sizeof(app->new_file_name));
      text_input_reset(app->text_input);
      text_input_set_header_text(app->text_input, "Enter file name:");
      text_input_set_result_callback(app->text_input, file_name_input_callback, app, app->new_file_name, sizeof(app->new_file_name), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
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

    // File name has been entered
    case 300:
      memset(app->username, 0, sizeof(app->username));
      text_input_reset(app->text_input);
      text_input_set_header_text(app->text_input, "Enter username:");
      text_input_set_result_callback(app->text_input, username_input_callback, app, app->username, sizeof(app->username), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
      return true;
      break;

    // Username has been entered
    case 301:
      // TODO add submenu to allow password generation
      memset(app->password, 0, sizeof(app->password));
      text_input_reset(app->text_input);
      text_input_set_header_text(app->text_input, "Enter password:");
      text_input_set_result_callback(app->text_input, password_input_callback, app, app->password, sizeof(app->password), true);

      app->current_view = ViewTextInput;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewTextInput);
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
      app->current_view = ViewManageMenu;
      view_dispatcher_switch_to_view(app->view_dispatcher, ViewManageMenu);
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
  app->widget = widget_alloc();
  app->status_widget = widget_alloc();
  app->loading = loading_alloc();
  app->current_view = ViewInitmenu;
  app->file_path = furi_string_alloc();
  app->text_input = text_input_alloc();

  // Add items to the init menu
  submenu_add_item(app->initmenu, "Scan RFID key", MenuScanRFID, menu_callback, app->view_dispatcher);
  submenu_add_item(app->initmenu, "Create RFID key", MenuCreateRFID, menu_callback, app->view_dispatcher);

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

  // Allocate the RFID dictionary and worker
  app->rfid_dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
  app->rfid_worker = lfrfid_worker_alloc(app->rfid_dict);

  // Add the menu to the dispatcher
  view_dispatcher_add_view(app->view_dispatcher, ViewInitmenu, submenu_get_view(app->initmenu));
  view_dispatcher_add_view(app->view_dispatcher, ViewManageMenu, submenu_get_view(app->managemenu));
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
  lfrfid_worker_free(app->rfid_worker);
  protocol_dict_free(app->rfid_dict);

  view_dispatcher_remove_view(app->view_dispatcher, ViewInitmenu);
  submenu_free(app->initmenu);
  view_dispatcher_remove_view(app->view_dispatcher, ViewManageMenu);
  submenu_free(app->managemenu);

  view_dispatcher_remove_view(app->view_dispatcher, ViewWidget);
  widget_free(app->widget);
  view_dispatcher_remove_view(app->view_dispatcher, ViewStatusWidget);
  widget_free(app->status_widget);

  view_dispatcher_remove_view(app->view_dispatcher, ViewLoading);
  loading_free(app->loading);

  furi_string_free(app->file_path);

  view_dispatcher_remove_view(app->view_dispatcher, ViewTextInput);
  text_input_free(app->text_input);

  view_dispatcher_free(app->view_dispatcher);
  furi_record_close(RECORD_GUI);
  free(app);

  return 0;
}
