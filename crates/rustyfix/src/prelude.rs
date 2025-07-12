//! Convenience re-exports of common traits and various items within `rustyfix`.
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "fix40")]
pub use crate::definitions::fix40;
#[cfg(feature = "fix41")]
pub use crate::definitions::fix41;
#[cfg(feature = "fix42")]
pub use crate::definitions::fix42;
#[cfg(feature = "fix43")]
pub use crate::definitions::fix43;
pub use crate::definitions::fix44;
#[cfg(feature = "fix50")]
pub use crate::definitions::fix50;
#[cfg(feature = "fix50sp1")]
pub use crate::definitions::fix50sp1;
#[cfg(feature = "fix50sp2")]
pub use crate::definitions::fix50sp2;
#[cfg(feature = "fixt11")]
pub use crate::definitions::fixt11;
pub use crate::dict::Dictionary;
pub use crate::{
    Buffer, FieldMap, FieldType, GetConfig, RepeatingGroup, SetField, StreamingDecoder, TagU32,
};
