use amp::Application;
use std::path::PathBuf;

#[test]
fn test_buffer_rendering() {
    let mut app = Application::new(&Vec::new()).unwrap();
    app.workspace
        .open_buffer(&PathBuf::from("src/commands/buffer.rs"))
        .unwrap();
    app.view
        .initialize_buffer(app.workspace.current_buffer.as_mut().unwrap())
        .unwrap();
    let buffer_data = app.workspace.current_buffer.as_ref().unwrap().data();

    let mut presenter = app.view.build_presenter().unwrap();
    assert!(presenter
        .print_buffer(
            app.workspace.current_buffer.as_ref().unwrap(),
            &buffer_data,
            &app.workspace.syntax_set,
            None,
            None,
        )
        .is_ok());
}

#[test]
fn test_scrolled_buffer_rendering() {
    for _ in 0..10 {let mut app = Application::new(&Vec::new()).unwrap();
    app.workspace
        .open_buffer(&PathBuf::from("src/commands/buffer.rs"))
        .unwrap();
    app.view
        .initialize_buffer(app.workspace.current_buffer.as_mut().unwrap())
        .unwrap();
    let buffer_data = app.workspace.current_buffer.as_ref().unwrap().data();

    // Scroll to the bottom of the buffer.
    app.workspace
        .current_buffer
        .as_mut()
        .unwrap()
        .cursor
        .move_to_last_line();
    app.view
        .scroll_to_cursor(app.workspace.current_buffer.as_ref().unwrap())
        .unwrap();

    let mut presenter = app.view.build_presenter().unwrap();
    assert!(presenter
        .print_buffer(
            app.workspace.current_buffer.as_ref().unwrap(),
            &buffer_data,
            &app.workspace.syntax_set,
            None,
            None,
        )
        .is_ok());}
}
