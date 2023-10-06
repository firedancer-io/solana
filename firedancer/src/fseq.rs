use std::ffi::c_ulong;
use firedancer_sys::*;

use crate::*;

pub struct FSeq {
    pub(crate) laddr: *mut c_ulong,
    pub(crate) diagnostic: *mut c_ulong,
    _workspace: Workspace,
}

unsafe impl Sync for FSeq {}
unsafe impl Send for FSeq {}

impl Drop for FSeq {
    fn drop(&mut self) {
        unsafe { tango::fd_fseq_leave(self.laddr) };
    }
}

impl FSeq {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
        let workspace = Workspace::map(gaddr)?;
        let laddr = tango::fd_fseq_join(workspace.laddr.as_ptr());
        if laddr.is_null() {
            Err(())
        } else {
            let diagnostic = tango::fd_fseq_app_laddr(laddr) as *mut c_ulong;
            if diagnostic.is_null() {
                Err(())
            } else {
                Ok(Self {
                    laddr,
                    diagnostic,
                    _workspace: workspace,
                })
            }
        }
  }

  pub fn rx_cr_return(&self, mcache: &MCache) {
      unsafe { tango::fd_fctl_rx_cr_return(self.laddr, mcache.sequence_number) }
  }
}
