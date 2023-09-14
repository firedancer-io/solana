use firedancer_sys::*;

use std::ffi::c_void;

use crate::*;

pub struct DCache {
    laddr: *mut u8,
    chunk0: u64,
    wmark: u64,
    chunk: u64,
    wksp: *mut util::fd_wksp_t,
    _workspace: Workspace,
}

unsafe impl Sync for DCache {}
unsafe impl Send for DCache {}

impl Drop for DCache {
    fn drop(&mut self) {
        unsafe { tango::fd_dcache_leave(self.laddr) };
    }
}

impl DCache {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T, mtu: u64) -> Result<Self, ()> {
      let workspace = Workspace::map(gaddr)?;
      let laddr = tango::fd_dcache_join(workspace.laddr.as_ptr());
      if laddr.is_null() {
          return Err(());
      }

      let wksp = util::fd_wksp_containing(laddr as *const c_void);
      let chunk0 = tango::fd_dcache_compact_chunk0(wksp as *const c_void, laddr as *const c_void);
      Ok(Self {
          laddr,
          chunk0,
          wmark: tango::fd_dcache_compact_wmark(wksp  as *const c_void, laddr  as *const c_void, mtu),
          chunk: chunk0,
          wksp,
          _workspace: workspace,
      })
  }

  pub fn chunk(&self) -> u64 {
    self.chunk
  }

  pub unsafe fn slice<'a>(&self, chunk: u64, offset: u64, len: u64) -> &'a[u8] {
    let laddr = tango::fd_chunk_to_laddr_const(self.wksp as *const c_void, chunk);
    std::slice::from_raw_parts(laddr.offset(offset as isize) as *const u8, len as usize)
  }

  pub unsafe fn write<'a>(&mut self, len: usize) -> &'a mut [u8] {
    std::slice::from_raw_parts_mut(tango::fd_chunk_to_laddr(self.wksp as *mut c_void, self.chunk) as *mut u8, len)
  }

  pub unsafe fn compact_next(&mut self, sz: u64) {
    self.chunk = tango::fd_dcache_compact_next(self.chunk, sz, self.chunk0, self.wmark)
  }
}
