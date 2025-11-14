pub mod tailq {
    use core::{
        marker::PhantomPinned,
        pin::Pin,
        ptr::{self, NonNull},
    };

    // In the original tailq source code, tailq head is defined as a separate
    // struct from tailq entry. However, tailq relies on head being layout
    // compatible with entry to cast it to entry, so we use the new type
    // pattern here.
    #[repr(transparent)]
    pub struct Head<T, const OFFSET: usize>(Entry<T>, PhantomPinned);

    impl<T, const OFFSET: usize> Head<T, OFFSET> {
        pub fn init(out: NonNull<Self>) {
            unsafe {
                let last = NonNull::from(&mut (*out.as_ptr()).0);
                out.write(Self(
                    Entry {
                        next: ptr::null_mut(),
                        prev: last,
                    },
                    PhantomPinned,
                ));
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

        pub fn push_back(self: Pin<&mut Self>, elt: NonNull<T>) {
            let mut entry_ptr = unsafe { Entry::new::<OFFSET>(elt) };
            let entry = unsafe { entry_ptr.as_mut() };
            entry.next = ptr::null_mut();
            entry.prev = self.0.prev;
            unsafe {
                let pinned_self = self.get_unchecked_mut();
                pinned_self.0.prev.as_mut().next = elt.as_ptr();
                pinned_self.0.prev = entry_ptr;
            }
        }

        pub fn remove(self: Pin<&mut Self>, elt: NonNull<T>) {
            unsafe {
                let entry = Entry::new::<OFFSET>(elt).as_mut();
                match NonNull::new(entry.next) {
                    Some(next) => Entry::new::<OFFSET>(next).as_mut().prev = entry.prev,
                    None => self.get_unchecked_mut().0.prev = entry.prev,
                }
                entry.prev.as_mut().next = entry.next;
            }
        }

        pub fn front(&self) -> Option<NonNull<T>> {
            self.0.next()
        }

        pub fn back(&self) -> Option<NonNull<T>> {
            self.0.prev()
        }

        pub fn drain(self: Pin<&mut Self>) -> Drain<T, OFFSET> {
            let ret = Drain {
                current: NonNull::new(self.0.next),
            };
            let pinned_self = unsafe { self.get_unchecked_mut() };
            pinned_self.0.next = ptr::null_mut();
            pinned_self.0.prev = NonNull::from_mut(&mut pinned_self.0);
            ret
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
    pub struct Entry<T> {
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

        pub fn next(&self) -> Option<NonNull<T>> {
            NonNull::new(self.next)
        }

        pub fn prev(&self) -> Option<NonNull<T>> {
            NonNull::new(unsafe { self.prev.as_ref().prev.as_ref().next })
        }
    }

    pub type Drain<T, const OFFSET: usize> = Iter<T, OFFSET>;
}
