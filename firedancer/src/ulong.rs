use crate::*;

pub struct ULong {
    pub value: *mut u64,
    _workspace: Workspace,
}

impl ULong {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
        let workspace = Workspace::map(gaddr)?;
        let laddr = workspace.laddr.as_ptr() as *mut u64;
        if laddr.is_null() {
            Err(())
        } else {
            Ok(Self {
                value: laddr,
                _workspace: workspace,
            })
        }
    }
}

unsafe impl Send for ULong {}
unsafe impl Sync for ULong {}
