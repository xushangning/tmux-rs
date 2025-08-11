pub mod tailq {
    use core::{
        mem::MaybeUninit,
        ptr::{self, NonNull},
    };

    // tailq relies on Head being layout compatible with Entry to cast it to Entry,
    // so we use the new type pattern here.
    #[repr(transparent)]
    pub struct Head<T, const OFFSET: usize>(Entry<T>);

    impl<T, const OFFSET: usize> Head<T, OFFSET> {
        // new() must not be implemented by returning a Head struct. Doing so
        // will incur a move and leave Head.last points to the old location
        // before the move.
        pub fn new(uninit: &mut MaybeUninit<Self>) -> &mut Self {
            unsafe {
                Self::init(uninit.as_mut_ptr());
                uninit.assume_init_mut()
            }
        }

        pub unsafe fn init(out: *mut Self) {
            unsafe {
                let last = NonNull::from(&mut (*out).0);
                out.write(Self(Entry::<T> {
                    next: ptr::null_mut(),
                    prev: last,
                }));
            }
        }

        pub fn iter(&self) -> Iter<T, OFFSET> {
            Iter {
                current: NonNull::new(self.0.next),
            }
        }

        pub fn is_empty(&self) -> bool {
            self.0.next.is_null()
        }

        pub fn push_back(&mut self, elt: NonNull<T>) {
            let mut entry_ptr = unsafe { Entry::new::<OFFSET>(elt) };
            let entry = unsafe { entry_ptr.as_mut() };
            entry.next = ptr::null_mut();
            entry.prev = self.0.prev;
            unsafe {
                self.0.prev.as_mut().next = elt.as_ptr();
                self.0.prev = entry_ptr;
            }
        }

        pub fn front(&self) -> Option<NonNull<T>> {
            NonNull::new(self.0.next)
        }
    }

    impl<T, const OFFSET: usize> IntoIterator for &Head<T, OFFSET> {
        type Item = NonNull<T>;
        type IntoIter = Iter<T, OFFSET>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    pub struct Iter<T, const OFFSET: usize> {
        current: Option<NonNull<T>>,
    }

    impl<T, const OFFSET: usize> Iterator for Iter<T, OFFSET> {
        type Item = NonNull<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.current.inspect(|&current| {
                self.current = NonNull::new(unsafe { Entry::new::<OFFSET>(current).as_ref().next })
            })
        }
    }

    #[repr(C)]
    pub(crate) struct Entry<T> {
        /// next element
        next: *mut T,
        /// In the original tmux source code, this field has type *mut T and
        /// and stores the address of the previous next element as explained
        /// in the comment. In reality, the stored address is sometimes cast to
        /// *mut Entry<T> to access the whole Entry struct, so we change the
        /// type to *mut Entry<T>.
        prev: NonNull<Entry<T>>,
    }

    impl<T> Entry<T> {
        unsafe fn new<const OFFSET: usize>(node: NonNull<T>) -> NonNull<Self> {
            unsafe { node.byte_add(OFFSET).cast() }
        }
    }
}
