use super::Error;
use std::{ffi, mem, ptr};

#[allow(
    non_upper_case_globals,
    non_snake_case,
    dead_code,
    non_camel_case_types
)]
mod dtrace;

#[link(name = "dtrace")]
unsafe extern "C" {}

pub struct Dtrace {
    buffers: Box<Vec<String>>,
    h: *mut dtrace::dtrace_hdl_t,
}

impl Drop for Dtrace {
    fn drop(&mut self) {
        unsafe {
            dtrace::dtrace_close(self.h);
        }
    }
}

unsafe impl Send for Dtrace {}

impl Dtrace {
    pub fn new() -> Result<Self, Error> {
        let mut err = 0;
        let h = unsafe { dtrace::dtrace_open(dtrace::DTRACE_VERSION as _, 0, &mut err) };
        if h.is_null() {
            return Err(Error::DTrace(err));
        }
        let mut dt = Self {
            buffers: Box::new(vec![]),
            h,
        };

        err = unsafe {
            dtrace::dtrace_handle_buffered(
                dt.h,
                Some(handle_buffered),
                (&mut *dt.buffers) as *mut _ as _,
            )
        };
        if err != 0 {
            return Err(Error::DTrace(err));
        }

        Ok(dt)
    }

    fn last_error(&mut self) -> ffi::c_int {
        unsafe { dtrace::dtrace_errno(self.h) }
    }

    pub fn setopt(&mut self, opt: &ffi::CStr, val: &ffi::CStr) -> Result<(), Error> {
        let err = unsafe { dtrace::dtrace_setopt(self.h, opt.as_ptr(), val.as_ptr()) };
        if err != 0 {
            Err(Error::DTrace(err))
        } else {
            Ok(())
        }
    }

    pub fn exec_program(&mut self, script: &ffi::CStr) -> Result<(), Error> {
        let prog = unsafe {
            dtrace::dtrace_program_strcompile(
                self.h,
                script.as_ptr(),
                dtrace::dtrace_probespec_DTRACE_PROBESPEC_NAME,
                dtrace::DTRACE_C_ZDEFS,
                0,
                ptr::null_mut(),
            )
        };
        if prog.is_null() {
            return Err(Error::DTrace(self.last_error()));
        }

        let mut info: dtrace::dtrace_proginfo_t = unsafe { mem::zeroed() };
        let err = unsafe { dtrace::dtrace_program_exec(self.h, prog, &mut info) };
        if err != 0 {
            return Err(Error::DTrace(err));
        }
        Ok(())
    }

    pub fn go(&mut self) -> Result<(), Error> {
        let err = unsafe { dtrace::dtrace_go(self.h) };
        if err != 0 {
            Err(Error::DTrace(err))
        } else {
            Ok(())
        }
    }

    pub fn stop(&mut self) -> Result<(), Error> {
        let err = unsafe { dtrace::dtrace_stop(self.h) };
        if err != 0 {
            Err(Error::DTrace(err))
        } else {
            Ok(())
        }
    }

    pub fn work(&mut self, mut f: impl FnMut(&str)) -> Result<bool, Error> {
        unsafe { dtrace::dtrace_sleep(self.h) };

        let status = unsafe {
            dtrace::dtrace_work(
                self.h,
                ptr::null_mut(),
                None,
                Some(chewrec),
                ptr::null_mut(),
            )
        };
        match status {
            dtrace::dtrace_workstatus_t_DTRACE_WORKSTATUS_OKAY
            | dtrace::dtrace_workstatus_t_DTRACE_WORKSTATUS_DONE => {}
            dtrace::dtrace_workstatus_t_DTRACE_WORKSTATUS_ERROR => {
                return Err(Error::DTrace(self.last_error()));
            }
            _ => unreachable!(),
        }

        for buf in self.buffers.iter() {
            f(buf);
        }
        self.buffers.clear();

        Ok(status == dtrace::dtrace_workstatus_t_DTRACE_WORKSTATUS_DONE)
    }
}

unsafe extern "C" fn handle_buffered(
    data: *const dtrace::dtrace_bufdata_t,
    context: *mut ffi::c_void,
) -> ffi::c_int {
    let buf = (*data).dtbda_buffered;
    if !buf.is_null() {
        let buffers = &mut *(context as *mut Vec<String>);
        buffers.push(ffi::CStr::from_ptr(buf).to_string_lossy().into_owned());
    }
    dtrace::DTRACE_HANDLE_OK as _
}

unsafe extern "C" fn chewrec(
    _data: *const dtrace::dtrace_probedata_t,
    rec: *const dtrace::dtrace_recdesc_t,
    _arg: *mut ffi::c_void,
) -> ffi::c_int {
    if rec.is_null() {
        return dtrace::DTRACE_CONSUME_NEXT as _;
    }

    match unsafe { (*rec).dtrd_action } as u32 {
        dtrace::DTRACEACT_DIFEXPR | dtrace::DTRACEACT_EXIT => dtrace::DTRACE_CONSUME_NEXT as _,
        _ => dtrace::DTRACE_CONSUME_THIS as _,
    }
}
