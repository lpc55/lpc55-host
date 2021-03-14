use pyo3::prelude::*;

use pyo3::exceptions::PyValueError;

#[pymodule]
fn lpc55(_py: Python, m: &PyModule) -> PyResult<()> {

    #[pyclass(freelist = 1000)]
    struct Bootloader {
        inner: lpc55::Bootloader,
    }


    #[pymethods]
    impl Bootloader {
        #[new]
        fn try_new(vid: Option<u16>, pid: Option<u16>) -> PyResult<Self> {
            lpc55::Bootloader::try_new(vid, pid)
                .ok_or(PyErr::new::<PyValueError, &str>("No bootloaders found. Check device is in bootloader mode."))
                .map(|inner| Self { inner })
        }

        // fn list(self) -> Vec<Self> {
        //     lpc55::Bootloader::list()
        //         .iter()
        //         .map(|inner| Self { inner: *inner })
        //         .collect()
        // }

        // fn info(&self) {
        //     self.inner.info()
        // }

        #[getter]
        fn uuid(&self) -> u128 {
            self.inner.uuid
        }

    }

     m.add_class::<Bootloader>()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
