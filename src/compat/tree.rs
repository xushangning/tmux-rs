pub mod rb {
    use core::{ffi::c_int, ptr::NonNull};

    #[repr(C)]
    pub struct Head<T, const OFFSET: usize> {
        root: Option<NonNull<T>>,
    }

    impl<T, const OFFSET: usize> Head<T, OFFSET> {
        pub const fn new() -> Self {
            Self { root: None }
        }

        pub fn is_empty(&self) -> bool {
            self.root.is_none()
        }

        pub fn iter(&self) -> Iter<T, OFFSET> {
            Iter {
                current: self.root.map(|root| Entry::front::<OFFSET>(root)),
            }
        }
    }

    impl<T, const OFFSET: usize> Default for Head<T, OFFSET> {
        fn default() -> Self {
            Self::new()
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
            self.current
                .inspect(|&current| self.current = Entry::successor::<OFFSET>(current))
        }
    }

    #[repr(C)]
    pub struct Entry<T> {
        left: *mut T,
        right: *mut T,
        parent: *mut T,
        color: c_int,
    }

    impl<T> Entry<T> {
        unsafe fn new<const OFFSET: usize>(node: NonNull<T>) -> NonNull<Self> {
            unsafe { node.byte_add(OFFSET).cast() }
        }

        fn front<const OFFSET: usize>(mut root: NonNull<T>) -> NonNull<T> {
            while let Some(next) = NonNull::new(unsafe { Self::new::<OFFSET>(root).as_ref() }.left)
            {
                root = next;
            }
            root
        }

        fn successor<const OFFSET: usize>(mut current: NonNull<T>) -> Option<NonNull<T>> {
            let entry = unsafe { Self::new::<OFFSET>(current).as_ref() };
            match NonNull::new(entry.right) {
                Some(right) => Some(Entry::front::<OFFSET>(right)),
                None => {
                    let mut parent_ptr = entry.parent;
                    while let Some(parent) = NonNull::new(parent_ptr) {
                        let parent_entry = unsafe { Self::new::<OFFSET>(parent).as_ref() };
                        if current.as_ptr() == parent_entry.left {
                            return Some(parent);
                        }
                        parent_ptr = parent_entry.parent;
                        current = parent;
                    }

                    None
                }
            }
        }
    }
}
