use firedancer_sys::*;

use crate::*;

pub struct Cnc {
    laddr: *mut tango::fd_cnc_t,
    _workspace: Workspace,
}

impl Drop for Cnc {
    fn drop(&mut self) {
        unsafe { tango::fd_cnc_leave(self.laddr) };
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum CncSignal {
    Run = tango::FD_CNC_SIGNAL_RUN,
    Boot = tango::FD_CNC_SIGNAL_BOOT,
    Fail = tango::FD_CNC_SIGNAL_FAIL,
    Halt = tango::FD_CNC_SIGNAL_HALT,
}

impl Cnc {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
        let workspace = Workspace::map(gaddr)?;
        let laddr = tango::fd_cnc_join(workspace.laddr.as_ptr());
        if laddr.is_null() {
            Err(())
        } else {
            Ok(Self {
                laddr,
                _workspace: workspace,
            })
        }
    }

    pub fn query(&self) -> u64 {
        unsafe { tango::fd_cnc_signal_query(self.laddr) }
    }

    pub fn signal(&self, signal: u64) {
        unsafe { tango::fd_cnc_signal(self.laddr, signal) }
    }

    pub fn heartbeat(&self, now: i64) {
        unsafe { tango::fd_cnc_heartbeat(self.laddr, now) }
    }
}
