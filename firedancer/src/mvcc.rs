use firedancer_sys::*;

use crate::*;

pub struct Mvcc {
    laddr: *mut tango::fd_mvcc_t,
    app_len: usize,
    app_laddr: *mut u8,
    _workspace: Workspace,
}

impl Drop for Mvcc {
    fn drop(&mut self) {
        unsafe { tango::fd_mvcc_leave(self.laddr) };
    }
}

impl Mvcc {
  pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
    let workspace = Workspace::map(gaddr)?;
    let laddr = tango::fd_mvcc_join(workspace.laddr.as_ptr());
    if laddr.is_null() {
        Err(())
    } else {
        let app_laddr = tango::fd_mvcc_app_laddr(laddr) as *mut u8;
        if app_laddr.is_null() {
            Err(())
        } else {
            let app_len = tango::fd_mvcc_app_sz(laddr);
            if app_len == 0 {
                Err(())
            } else {
              Ok(Self {
                  laddr,
                  app_len: app_len.try_into().unwrap(),
                  app_laddr,
                  _workspace: workspace,
              })
          }
        }
    }
  }

  pub fn begin_write(&mut self) -> &mut [u8] {
    unsafe {
      tango::fd_mvcc_begin_write(self.laddr);
      std::slice::from_raw_parts_mut(self.app_laddr, self.app_len )
    }
  }

  pub fn end_write(&mut self) {
    unsafe { tango::fd_mvcc_end_write(self.laddr) }
  }
}
