use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

pub struct CancelableJoinHandle<T> {
    handle: thread::JoinHandle<T>,
    running: Arc<AtomicBool>,
}

/// Spawns a cancelable thread that can be joined later.
/// The thread is passed an `Arc<AtomicBool>` that can be used to check if the thread should stop running.
/// The thread is requested to stop running when the `AtomicBool` is set to `false`.
pub fn spawn_cancelable<T: Send + Sync + 'static>(
    func: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
) -> CancelableJoinHandle<T> {
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    let handle = thread::spawn(move || func(r));
    CancelableJoinHandle { handle, running }
}

impl<T> CancelableJoinHandle<T> {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    pub fn join(self) -> thread::Result<T> {
        self.running.store(false, Ordering::Relaxed);
        self.handle.join()
    }
}
