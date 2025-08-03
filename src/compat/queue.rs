pub mod tailq {
    use core::{
        mem::MaybeUninit,
        ptr::{self, NonNull},
    };

    #[repr(C)]
    pub struct Head<T, const OFFSET: usize> {
        first: *mut T,
        last: NonNull<*mut T>,
    }

    impl<T, const OFFSET: usize> Head<T, OFFSET> {
        // new() must not be implemented by returning a Head struct. Doing so
        // will incur a move and leave head.last points to the old location
        // before the move.
        pub fn new(uninit: &mut MaybeUninit<Self>) -> &mut Self {
            let last = NonNull::from(unsafe { &mut (*uninit.as_mut_ptr()).first });
            uninit.write(Self {
                first: ptr::null_mut(),
                last,
            })
        }

        pub fn iter(&self) -> Iter<T, OFFSET> {
            Iter {
                current: NonNull::new(self.first),
            }
        }

        pub fn is_empty(&self) -> bool {
            self.first.is_null()
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
    struct Entry<T> {
        /// next element
        next: *mut T,
        /// In the original tmux source code, this field has type *mut T and
        /// and stores the address of the previous next element as explained
        /// in the comment. In reality, the stored address is sometimes cast to
        /// *mut Entry<T> to access the whole Entry struct, so we change the
        /// type to *mut Entry<T>.
        prev: *mut Entry<T>,
    }

    impl<T> Entry<T> {
        unsafe fn new<const OFFSET: usize>(node: NonNull<T>) -> NonNull<Self> {
            unsafe { node.byte_add(OFFSET).cast() }
        }
    }
}
