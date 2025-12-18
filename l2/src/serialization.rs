/// Serialization and deserialization module for interoperability
/// Supports Base 10, Base 16 (hexadecimal), and Base64 formats
/// 
/// This module enables cross-platform and cross-implementation interoperability
/// by providing standard serialization formats for all cryptographic structures.
use crate::bigint::BigUint;
use crate::field::FieldElement;
use crate::binary_field::BinaryFieldElement;
use crate::extension_field::ExtensionFieldElement;
use crate::elliptic_curve::EllipticCurvePoint;
use crate::binary_elliptic_curve::BinaryEllipticCurvePoint;
use crate::polynomial::Polynomial;
use serde::{Serialize, Deserialize};
use base64::Engine;

// ==================== Serialization Format Enum ====================

/// Format for serializing numeric values
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SerializationFormat {
    #[serde(rename = "base10")]
    #[default]
    Base10,
    #[serde(rename = "base16")]
    Base16,
    #[serde(rename = "base64")]
    Base64,
}

impl SerializationFormat {
    /// Convert BigUint to string in this format
    pub fn encode(&self, value: &BigUint) -> String {
        match self {
            SerializationFormat::Base10 => value.to_base10(),
            SerializationFormat::Base16 => value.to_base16(),
            SerializationFormat::Base64 => value.to_base64(),
        }
    }

    /// Parse string in this format to BigUint
    pub fn decode(&self, s: &str) -> Result<BigUint, String> {
        match self {
            SerializationFormat::Base10 => BigUint::from_base10(s),
            SerializationFormat::Base16 => BigUint::from_base16(s),
            SerializationFormat::Base64 => BigUint::from_base64(s),
        }
    }

    /// Encode bytes in this format
    pub fn encode_bytes(&self, bytes: &[u8]) -> String {
        match self {
            SerializationFormat::Base10 => BigUint::from_bytes_be(bytes).to_base10(),
            SerializationFormat::Base16 => bytes_to_hex(bytes),
            SerializationFormat::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    /// Decode bytes from this format
    pub fn decode_bytes(&self, s: &str) -> Result<Vec<u8>, String> {
        match self {
            SerializationFormat::Base10 => {
                let num = BigUint::from_base10(s)?;
                Ok(num.to_bytes_be())
            }
            SerializationFormat::Base16 => hex_to_bytes(s),
            SerializationFormat::Base64 => {
                base64::engine::general_purpose::STANDARD.decode(s)
                    .map_err(|e| format!("Base64 decode error: {}", e))
            }
        }
    }
}

// ==================== Field Element Serialization ====================

/// Serializable representation of a field element (Fp)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableFieldElement {
    pub value: String,
    pub modulus: String,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializableFieldElement {
    /// Convert a FieldElement to serializable form with specified format
    pub fn from_field_element(elem: &FieldElement, format: SerializationFormat) -> Self {
        SerializableFieldElement {
            value: format.encode(elem.value()),
            modulus: format.encode(elem.modulus()),
            format,
        }
    }

    /// Convert back to FieldElement
    pub fn to_field_element(&self) -> Result<FieldElement, String> {
        let value = self.format.decode(&self.value)?;
        let modulus = self.format.decode(&self.modulus)?;
        Ok(FieldElement::new(value, modulus))
    }

    /// Create from strings with specified format
    pub fn new(value: &str, modulus: &str, format: SerializationFormat) -> Result<Self, String> {
        let value_big = format.decode(value)?;
        let modulus_big = format.decode(modulus)?;
        let elem = FieldElement::new(value_big, modulus_big);
        Ok(Self::from_field_element(&elem, format))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Binary Field Element Serialization ====================

/// Serializable representation of a binary field element (F2^m)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableBinaryFieldElement {
    pub value: String,
    pub irreducible: String,
    pub degree: usize,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializableBinaryFieldElement {
    /// Convert a BinaryFieldElement to serializable form with specified format
    pub fn from_binary_field_element(elem: &BinaryFieldElement, format: SerializationFormat) -> Self {
        let value_bytes = elem.to_bytes();
        let irreducible_bytes = elem.irreducible();
        
        SerializableBinaryFieldElement {
            value: format.encode_bytes(&value_bytes),
            irreducible: format.encode_bytes(irreducible_bytes),
            degree: elem.degree(),
            format,
        }
    }

    /// Convert back to BinaryFieldElement
    pub fn to_binary_field_element(&self) -> Result<BinaryFieldElement, String> {
        let value_bytes = self.format.decode_bytes(&self.value)?;
        let irreducible = self.format.decode_bytes(&self.irreducible)?;
        
        Ok(BinaryFieldElement::new(value_bytes, irreducible, self.degree))
    }

    /// Create from strings with specified format
    pub fn new(value: &str, irreducible: &str, degree: usize, format: SerializationFormat) -> Result<Self, String> {
        let value_bytes = format.decode_bytes(value)?;
        let irreducible_bytes = format.decode_bytes(irreducible)?;
        let elem = BinaryFieldElement::new(value_bytes, irreducible_bytes, degree);
        Ok(Self::from_binary_field_element(&elem, format))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Extension Field Element Serialization ====================

/// Serializable representation of an extension field element (Fp^k)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableExtensionFieldElement {
    pub coefficients: Vec<String>,
    pub irreducible_coeffs: Vec<String>,
    pub modulus: String,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializableExtensionFieldElement {
    /// Convert an ExtensionFieldElement to serializable form with specified format
    pub fn from_extension_field_element(elem: &ExtensionFieldElement, format: SerializationFormat) -> Self {
        let coeffs = elem.coefficients();
        let irreducible_coeffs = elem.irreducible().coeffs();
        
        SerializableExtensionFieldElement {
            coefficients: coeffs.iter().map(|c| format.encode(c.value())).collect(),
            irreducible_coeffs: irreducible_coeffs.iter()
                .map(|c| format.encode(c.value())).collect(),
            modulus: format.encode(elem.modulus()),
            format,
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Polynomial Serialization ====================

/// Serializable representation of a polynomial over Fp
/// Stores coefficients from lowest to highest degree: [a0, a1, a2, ...] = a0 + a1*X + a2*X^2 + ...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializablePolynomial {
    pub coefficients: Vec<String>,
    pub modulus: String,
    pub degree: i32,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializablePolynomial {
    /// Convert a Polynomial<FieldElement> to serializable form with specified format
    pub fn from_polynomial(poly: &Polynomial<FieldElement>, format: SerializationFormat) -> Self {
        let coeffs = poly.coeffs();
        let modulus = if !coeffs.is_empty() {
            format.encode(coeffs[0].modulus())
        } else {
            "0".to_string()
        };
        
        SerializablePolynomial {
            coefficients: coeffs.iter().map(|c| format.encode(c.value())).collect(),
            modulus,
            degree: poly.degree(),
            format,
        }
    }

    /// Convert back to Polynomial<FieldElement>
    pub fn to_polynomial(&self) -> Result<Polynomial<FieldElement>, String> {
        if self.coefficients.is_empty() {
            return Ok(Polynomial::zero());
        }
        
        let modulus = self.format.decode(&self.modulus)?;
        let coeffs: Result<Vec<FieldElement>, String> = self.coefficients.iter()
            .map(|c| {
                let value = self.format.decode(c)?;
                Ok(FieldElement::new(value, modulus.clone()))
            })
            .collect();
        
        Ok(Polynomial::new(coeffs?))
    }

    /// Create from coefficient strings with specified format
    pub fn new(coeffs: &[&str], modulus: &str, format: SerializationFormat) -> Result<Self, String> {
        let modulus_big = format.decode(modulus)?;
        let field_coeffs: Result<Vec<FieldElement>, String> = coeffs.iter()
            .map(|c| {
                let value = format.decode(c)?;
                Ok(FieldElement::new(value, modulus_big.clone()))
            })
            .collect();
        
        let poly = Polynomial::new(field_coeffs?);
        Ok(Self::from_polynomial(&poly, format))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Elliptic Curve Point Serialization ====================

/// Serializable representation of an elliptic curve point over Fp
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum SerializableECPoint {
    #[serde(rename = "infinity")]
    Infinity {
        #[serde(default)]
        format: SerializationFormat,
    },
    #[serde(rename = "point")]
    Point {
        x: String,
        y: String,
        #[serde(default)]
        format: SerializationFormat,
    },
}

impl SerializableECPoint {
    /// Convert an EllipticCurvePoint to serializable form with specified format
    pub fn from_ec_point(point: &EllipticCurvePoint<FieldElement>, format: SerializationFormat) -> Self {
        match point {
            EllipticCurvePoint::Infinity => SerializableECPoint::Infinity { format },
            EllipticCurvePoint::Point { x, y } => SerializableECPoint::Point {
                x: format.encode(x.value()),
                y: format.encode(y.value()),
                format,
            },
        }
    }

    /// Get compressed point format (x-coordinate only + sign bit)
    pub fn to_compressed(&self) -> Result<String, String> {
        match self {
            SerializableECPoint::Infinity { .. } => Ok("infinity".to_string()),
            SerializableECPoint::Point { x, y, format } => {
                let y_big = format.decode(y)?;
                let prefix = if y_big.is_even() { "02" } else { "03" };
                // For compression, always use hex
                let x_hex = SerializationFormat::Base16.encode(&format.decode(x)?);
                Ok(format!("{}{}", prefix, x_hex))
            }
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

/// Serializable representation of an elliptic curve over Fp
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableEllipticCurve {
    pub curve_equation: String, // "y^2 = x^3 + ax + b"
    pub a: String,
    pub b: String,
    pub modulus: String,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializableEllipticCurve {
    /// Create from curve parameters with specified format
    pub fn new(a: &FieldElement, b: &FieldElement, format: SerializationFormat) -> Self {
        SerializableEllipticCurve {
            curve_equation: "y^2 = x^3 + ax + b".to_string(),
            a: format.encode(a.value()),
            b: format.encode(b.value()),
            modulus: format.encode(a.modulus()),
            format,
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Binary Elliptic Curve Point Serialization ====================

/// Serializable representation of a binary elliptic curve point
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum SerializableBinaryECPoint {
    #[serde(rename = "infinity")]
    Infinity {
        #[serde(default)]
        format: SerializationFormat,
    },
    #[serde(rename = "point")]
    Point {
        x: String,
        y: String,
        #[serde(default)]
        format: SerializationFormat,
    },
}

impl SerializableBinaryECPoint {
    /// Convert a BinaryEllipticCurvePoint to serializable form with specified format
    pub fn from_binary_ec_point(point: &BinaryEllipticCurvePoint, format: SerializationFormat) -> Self {
        match point {
            BinaryEllipticCurvePoint::Infinity => SerializableBinaryECPoint::Infinity { format },
            BinaryEllipticCurvePoint::Point { x, y } => {
                let x_bytes = x.to_bytes();
                let y_bytes = y.to_bytes();
                
                SerializableBinaryECPoint::Point {
                    x: format.encode_bytes(&x_bytes),
                    y: format.encode_bytes(&y_bytes),
                    format,
                }
            }
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

/// Serializable representation of a binary elliptic curve
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableBinaryEllipticCurve {
    pub curve_equation: String, // "y^2 + xy = x^3 + ax^2 + b"
    pub a: String,
    pub b: String,
    pub irreducible: String,
    pub degree: usize,
    #[serde(default)]
    pub format: SerializationFormat,
}

impl SerializableBinaryEllipticCurve {
    /// Create from curve parameters with specified format
    pub fn new(a: &BinaryFieldElement, b: &BinaryFieldElement, format: SerializationFormat) -> Self {
        SerializableBinaryEllipticCurve {
            curve_equation: "y^2 + xy = x^3 + ax^2 + b".to_string(),
            a: format.encode_bytes(&a.to_bytes()),
            b: format.encode_bytes(&b.to_bytes()),
            irreducible: format.encode_bytes(a.irreducible()),
            degree: a.degree(),
            format,
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

// ==================== Helper Functions ====================

/// Convert bytes to hexadecimal string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hexadecimal string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
    
    if hex.is_empty() {
        return Ok(vec![0]);
    }

    let chars: Vec<char> = hex.chars().collect();
    let padded = if chars.len() % 2 == 1 {
        let mut p = vec!['0'];
        p.extend(chars);
        p
    } else {
        chars
    };

    let mut bytes = Vec::new();
    for chunk in padded.chunks(2) {
        let hex_str: String = chunk.iter().collect();
        let byte = u8::from_str_radix(&hex_str, 16)
            .map_err(|_| "Invalid hex string".to_string())?;
        bytes.push(byte);
    }

    Ok(bytes)
}

// ==================== Comprehensive Serialization Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_base10() {
        let num = BigUint::from_u64(12345);
        let s = num.to_base10();
        assert_eq!(s, "12345");
        
        let parsed = BigUint::from_base10(&s).unwrap();
        assert_eq!(parsed, num);
    }

    #[test]
    fn test_biguint_base16() {
        let num = BigUint::from_u64(0xABCD);
        let s = num.to_base16();
        assert_eq!(s, "abcd");
        
        let parsed = BigUint::from_base16(&s).unwrap();
        assert_eq!(parsed, num);
        
        // Test with 0x prefix
        let parsed2 = BigUint::from_base16("0xABCD").unwrap();
        assert_eq!(parsed2, num);
    }

    #[test]
    fn test_biguint_base64() {
        let num = BigUint::from_u64(123456789);
        let s = num.to_base64();
        
        let parsed = BigUint::from_base64(&s).unwrap();
        assert_eq!(parsed, num);
    }

    #[test]
    fn test_field_element_serialization() {
        let p = BigUint::from_u64(17);
        let elem = FieldElement::from_u64(5, p);
        
        let ser = SerializableFieldElement::from_field_element(&elem, SerializationFormat::Base10);
        assert_eq!(ser.value, "5");
        assert_eq!(ser.modulus, "17");
        assert_eq!(ser.format, SerializationFormat::Base10);
        
        let json = ser.to_json().unwrap();
        let deser = SerializableFieldElement::from_json(&json).unwrap();
        
        let elem2 = deser.to_field_element().unwrap();
        assert_eq!(elem, elem2);
    }

    #[test]
    fn test_binary_field_element_serialization() {
        let irreducible = vec![0b10011];
        let degree = 4;
        let elem = BinaryFieldElement::from_u64(0b1010, irreducible.clone(), degree);
        
        let ser = SerializableBinaryFieldElement::from_binary_field_element(&elem, SerializationFormat::Base16);
        
        let json = ser.to_json().unwrap();
        let deser = SerializableBinaryFieldElement::from_json(&json).unwrap();
        
        let elem2 = deser.to_binary_field_element().unwrap();
        assert_eq!(elem, elem2);
    }

    #[test]
    fn test_ec_point_serialization() {
        let p = BigUint::from_u64(17);
        let x = FieldElement::new(BigUint::from_u64(5), p.clone());
        let y = FieldElement::new(BigUint::from_u64(1), p.clone());
        let point = EllipticCurvePoint::<FieldElement>::Point { x, y };
        
        let ser = SerializableECPoint::from_ec_point(&point, SerializationFormat::Base10);
        let json = ser.to_json().unwrap();
        let deser = SerializableECPoint::from_json(&json).unwrap();
        
        match (ser, deser) {
            (SerializableECPoint::Point { x: x1, y: y1, .. },
             SerializableECPoint::Point { x: x2, y: y2, .. }) => {
                assert_eq!(x1, x2);
                assert_eq!(y1, y2);
            }
            _ => panic!("Expected Point"),
        }
    }

    #[test]
    fn test_infinity_point_serialization() {
        let point = EllipticCurvePoint::<FieldElement>::Infinity;
        let ser = SerializableECPoint::from_ec_point(&point, SerializationFormat::Base10);
        
        let json = ser.to_json().unwrap();
        let deser = SerializableECPoint::from_json(&json).unwrap();
        
        assert!(matches!(deser, SerializableECPoint::Infinity { .. }));
    }

    #[test]
    fn test_round_trip_all_formats() {
        // Test BigUint with all three formats
        let num = BigUint::from_u64(987654321);
        
        // Base 10
        let b10 = num.to_base10();
        assert_eq!(BigUint::from_base10(&b10).unwrap(), num);
        
        // Base 16
        let b16 = num.to_base16();
        assert_eq!(BigUint::from_base16(&b16).unwrap(), num);
        
        // Base 64
        let b64 = num.to_base64();
        assert_eq!(BigUint::from_base64(&b64).unwrap(), num);
    }

    #[test]
    fn test_polynomial_serialization() {
        // Create a polynomial: 3 + 5x + 2x^2 over F_17
        let p = BigUint::from_u64(17);
        let coeffs = vec![
            FieldElement::new(BigUint::from_u64(3), p.clone()),
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(2), p.clone()),
        ];
        let poly = Polynomial::new(coeffs);
        
        // Serialize
        let ser = SerializablePolynomial::from_polynomial(&poly, SerializationFormat::Base10);
        assert_eq!(ser.coefficients, vec!["3", "5", "2"]);
        assert_eq!(ser.modulus, "17");
        assert_eq!(ser.degree, 2);
        assert_eq!(ser.format, SerializationFormat::Base10);
        
        // JSON round trip
        let json = ser.to_json().unwrap();
        let deser = SerializablePolynomial::from_json(&json).unwrap();
        
        // Deserialize back
        let poly2 = deser.to_polynomial().unwrap();
        assert_eq!(poly, poly2);
    }

    #[test]
    fn test_polynomial_with_formats() {
        // Create polynomial from strings with different formats
        let coeffs = vec!["1", "2", "3"];
        let ser = SerializablePolynomial::new(&coeffs, "17", SerializationFormat::Base10).unwrap();
        
        assert_eq!(ser.coefficients, vec!["1", "2", "3"]);
        assert_eq!(ser.degree, 2);
        
        let poly = ser.to_polynomial().unwrap();
        assert_eq!(poly.degree(), 2);
        
        // Test with hex format
        let ser_hex = SerializablePolynomial::new(&["a", "b", "c"], "11", SerializationFormat::Base16).unwrap();
        assert_eq!(ser_hex.format, SerializationFormat::Base16);
    }

    #[test]
    fn test_zero_polynomial_serialization() {
        // Test zero polynomial
        let poly: Polynomial<FieldElement> = Polynomial::zero();
        
        let ser = SerializablePolynomial::from_polynomial(&poly, SerializationFormat::Base10);
        assert_eq!(ser.coefficients.len(), 0);
        assert_eq!(ser.degree, -1);
        
        let poly2 = ser.to_polynomial().unwrap();
        assert!(poly2.is_zero());
        assert_eq!(poly2.degree(), -1);
    }
}
