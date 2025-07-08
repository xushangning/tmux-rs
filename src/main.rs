use core::marker::{PhantomData, PhantomPinned};

#[repr(C)]
struct EventBase {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    fn osdep_event_init() -> *mut EventBase;
}

fn main() {
    dbg!(unsafe { osdep_event_init() });
}
