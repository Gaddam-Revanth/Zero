// Probe actual ml-kem 0.3.0-rc.0 API
#[cfg(test)]
mod tests {
    #[test]
    fn probe_ml_kem() {
        use ml_kem::*;
        use rand::rngs::OsRng;
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let (ct, ss1) = ek.encapsulate(&mut OsRng).unwrap();
        let ss2 = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
