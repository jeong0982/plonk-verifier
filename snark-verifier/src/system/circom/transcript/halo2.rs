use crate::{
    loader::{
        halo2::{EcPoint, EccInstructions, Halo2Loader, Scalar},
        native::{self, NativeLoader},
        Loader, ScalarLoader,
    },
    util::{
        arithmetic::{fe_to_fe, CurveAffine, PrimeField},
        hash::Poseidon,
        transcript::{Transcript, TranscriptRead, TranscriptWrite},
        Itertools,
    },
    Error,
};
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_wrong_ecc::BaseFieldEccChip;
use std::{
    io::{self, Read, Write},
    rc::Rc,
};

/// Encoding that encodes elliptic curve point into native field elements.
pub trait NativeEncoding<'a, C>: EccInstructions<'a, C>
where
    C: CurveAffine,
{
    /// Encode an elliptic curve point into field elements.
    fn encode(
        &self,
        ctx: &mut Self::Context,
        ec_point: &Self::AssignedEcPoint,
    ) -> Result<Vec<Self::AssignedScalar>, Error>;
}

impl<'a, C: CurveAffine, const LIMBS: usize, const BITS: usize> NativeEncoding<'a, C>
    for BaseFieldEccChip<C, LIMBS, BITS>
{
    fn encode(
        &self,
        _: &mut Self::Context,
        ec_point: &Self::AssignedEcPoint,
    ) -> Result<Vec<AssignedCell<C::Scalar, C::Scalar>>, crate::Error> {
        Ok(vec![
            ec_point.x().native().clone(),
            ec_point.y().native().clone(),
        ])
    }
}

#[derive(Debug)]
pub struct PoseidonTranscript<
    C,
    L,
    S,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> where
    C: CurveAffine,
    L: Loader<C>,
{
    loader: L,
    stream: S,
    buf: Poseidon<C::Scalar, <L as ScalarLoader<C::Scalar>>::LoadedScalar, T, RATE>,
    adjacent_challenge: Option<L::LoadedScalar>,
}

impl<'a, C, R, EccChip, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    PoseidonTranscript<C, Rc<Halo2Loader<'a, C, EccChip>>, Value<R>, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    R: Read,
    EccChip: NativeEncoding<'a, C>,
{
    pub fn new(loader: &Rc<Halo2Loader<'a, C, EccChip>>, stream: Value<R>) -> Self {
        let buf = Poseidon::new(loader, R_F, R_P);
        Self {
            loader: loader.clone(),
            stream,
            buf,
            adjacent_challenge: None,
        }
    }
}

impl<'a, C, R, EccChip, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    Transcript<C, Rc<Halo2Loader<'a, C, EccChip>>>
    for PoseidonTranscript<C, Rc<Halo2Loader<'a, C, EccChip>>, Value<R>, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    R: Read,
    EccChip: NativeEncoding<'a, C>,
{
    fn loader(&self) -> &Rc<Halo2Loader<'a, C, EccChip>> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar<'a, C, EccChip> {
        if self.adjacent_challenge.is_some() {
            self.buf.update(&[self.adjacent_challenge.take().unwrap()]);
        }
        self.buf.squeeze()
    }

    fn common_scalar(&mut self, scalar: &Scalar<'a, C, EccChip>) -> Result<(), Error> {
        self.adjacent_challenge = None;
        self.buf.update(&[scalar.clone()]);
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint<'a, C, EccChip>) -> Result<(), Error> {
        self.adjacent_challenge = None;
        let encoded = self
            .loader
            .ecc_chip()
            .encode(&mut self.loader.ctx_mut(), &ec_point.assigned())
            .map(|encoded| {
                encoded
                    .into_iter()
                    .map(|encoded| self.loader.scalar_from_assigned(encoded))
                    .collect_vec()
            })
            .map_err(|_| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point".to_string(),
                )
            })?;
        self.buf.update(&encoded);
        Ok(())
    }
}

impl<'a, C, R, EccChip, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    TranscriptRead<C, Rc<Halo2Loader<'a, C, EccChip>>>
    for PoseidonTranscript<C, Rc<Halo2Loader<'a, C, EccChip>>, Value<R>, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    R: Read,
    EccChip: NativeEncoding<'a, C>,
{
    fn read_scalar(&mut self) -> Result<Scalar<'a, C, EccChip>, Error> {
        let scalar = self.stream.as_mut().and_then(|stream| {
            let mut data = <C::Scalar as PrimeField>::Repr::default();
            if stream.read_exact(data.as_mut()).is_err() {
                return Value::unknown();
            }
            Option::<C::Scalar>::from(C::Scalar::from_repr(data))
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        });
        let scalar = self.loader.assign_scalar(scalar);
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint<'a, C, EccChip>, Error> {
        let ec_point = self.stream.as_mut().and_then(|stream| {
            let mut compressed = C::Repr::default();
            if stream.read_exact(compressed.as_mut()).is_err() {
                return Value::unknown();
            }
            Option::<C>::from(C::from_bytes(&compressed))
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        });
        let ec_point = self.loader.assign_ec_point(ec_point);
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C: CurveAffine, S, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    PoseidonTranscript<C, NativeLoader, S, T, RATE, R_F, R_P>
{
    pub fn new(stream: S) -> Self {
        Self {
            loader: NativeLoader,
            stream,
            buf: Poseidon::new(&NativeLoader, R_F, R_P),
            adjacent_challenge: None,
        }
    }
}

impl<C: CurveAffine, S, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    Transcript<C, NativeLoader> for PoseidonTranscript<C, NativeLoader, S, T, RATE, R_F, R_P>
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        if self.adjacent_challenge.is_some() {
            self.buf.update(&[self.adjacent_challenge.take().unwrap()]);
        }
        let challenge = self.buf.squeeze();
        self.adjacent_challenge = Some(challenge);
        challenge
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.adjacent_challenge = None;
        self.buf.update(&[*scalar]);
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        self.adjacent_challenge = None;
        let encoded: Vec<_> = Option::from(ec_point.coordinates().map(|coordinates| {
            [coordinates.x(), coordinates.y()]
                .into_iter()
                .cloned()
                .map(fe_to_fe)
                .collect_vec()
        }))
        .ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid elliptic curve point encoding in proof".to_string(),
            )
        })?;
        self.buf.update(&encoded);
        Ok(())
    }
}

impl<C, R, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    TranscriptRead<C, NativeLoader> for PoseidonTranscript<C, NativeLoader, R, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    R: Read,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let scalar = C::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid scalar encoding in proof".to_string(),
            )
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let mut data = C::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let ec_point = Option::<C>::from(C::from_bytes(&data)).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid elliptic curve point encoding in proof".to_string(),
            )
        })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, W, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    PoseidonTranscript<C, NativeLoader, W, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    W: Write,
{
    pub fn stream_mut(&mut self) -> &mut W {
        &mut self.stream
    }

    pub fn finalize(self) -> W {
        self.stream
    }
}

impl<C, W, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize> TranscriptWrite<C>
    for PoseidonTranscript<C, NativeLoader, W, T, RATE, R_F, R_P>
where
    C: CurveAffine,
    W: Write,
{
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), Error> {
        self.common_scalar(&scalar)?;
        let data = scalar.to_repr();
        self.stream_mut().write_all(data.as_ref()).map_err(|err| {
            Error::Transcript(
                err.kind(),
                "Failed to write scalar to transcript".to_string(),
            )
        })
    }

    fn write_ec_point(&mut self, ec_point: C) -> Result<(), Error> {
        self.common_ec_point(&ec_point)?;
        let data = ec_point.to_bytes();
        self.stream_mut().write_all(data.as_ref()).map_err(|err| {
            Error::Transcript(
                err.kind(),
                "Failed to write elliptic curve to transcript".to_string(),
            )
        })
    }
}
