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
use serde::{Serialize, Deserialize};
use base64::Engine;

// ==================== Field Element Serialization ====================

/// Serializable representation of a field element (Fp)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableFieldElement {
    #[serde(rename = "value_base10")]
    pub value_base10: String,
    #[serde(rename = "value_base16")]
    pub value_base16: String,
    #[serde(rename = "value_base64")]
    pub value_base64: String,
    #[serde(rename = "modulus_base10")]
    pub modulus_base10: String,
    #[serde(rename = "modulus_base16")]
    pub modulus_base16: String,
}

impl SerializableFieldElement {
    /// Convert a FieldElement to serializable form
    pub fn from_field_element(elem: &FieldElement) -> Self {
        SerializableFieldElement {
            value_base10: elem.value().to_base10(),
            value_base16: elem.value().to_base16(),
            value_base64: elem.value().to_base64(),
            modulus_base10: elem.modulus().to_base10(),
            modulus_base16: elem.modulus().to_base16(),
        }
    }

    /// Convert back to FieldElement (using base10 by default)
    pub fn to_field_element(&self) -> Result<FieldElement, String> {
        let value = BigUint::from_base10(&self.value_base10)?;
        let modulus = BigUint::from_base10(&self.modulus_base10)?;
        Ok(FieldElement::new(value, modulus))
    }

    /// Create from base10 strings
    pub fn from_base10(value: &str, modulus: &str) -> Result<Self, String> {
        let value_big = BigUint::from_base10(value)?;
        let modulus_big = BigUint::from_base10(modulus)?;
        let elem = FieldElement::new(value_big, modulus_big);
        Ok(Self::from_field_element(&elem))
    }

    /// Create from base16 strings
    pub fn from_base16(value: &str, modulus: &str) -> Result<Self, String> {
        let value_big = BigUint::from_base16(value)?;
        let modulus_big = BigUint::from_base16(modulus)?;
        let elem = FieldElement::new(value_big, modulus_big);
        Ok(Self::from_field_element(&elem))
    }

    /// Create from base64 strings
    pub fn from_base64(value: &str, modulus: &str) -> Result<Self, String> {
        let value_big = BigUint::from_base64(value)?;
        let modulus_big = BigUint::from_base64(modulus)?;
        let elem = FieldElement::new(value_big, modulus_big);
        Ok(Self::from_field_element(&elem))
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
    #[serde(rename = "value_base16")]
    pub value_base16: String,
    #[serde(rename = "value_base64")]
    pub value_base64: String,
    #[serde(rename = "irreducible_base16")]
    pub irreducible_base16: String,
    pub degree: usize,
}

impl SerializableBinaryFieldElement {
    /// Convert a BinaryFieldElement to serializable form
    pub fn from_binary_field_element(elem: &BinaryFieldElement) -> Self {
        let value_bytes = elem.to_bytes();
        let irreducible_bytes = elem.irreducible();
        
        SerializableBinaryFieldElement {
            value_base16: bytes_to_hex(&value_bytes),
            value_base64: base64::engine::general_purpose::STANDARD.encode(&value_bytes),
            irreducible_base16: bytes_to_hex(irreducible_bytes),
            degree: elem.degree(),
        }
    }

    /// Convert back to BinaryFieldElement
    pub fn to_binary_field_element(&self) -> Result<BinaryFieldElement, String> {
        let value_bytes = hex_to_bytes(&self.value_base16)?;
        let irreducible = hex_to_bytes(&self.irreducible_base16)?;
        
        Ok(BinaryFieldElement::new(value_bytes, irreducible, self.degree))
    }

    /// Create from hex strings
    #[allow(dead_code)]
    pub fn from_base16(value: &str, irreducible: &str, degree: usize) -> Result<Self, String> {
        let value_bytes = hex_to_bytes(value)?;
        let irreducible_bytes = hex_to_bytes(irreducible)?;
        let elem = BinaryFieldElement::new(value_bytes, irreducible_bytes, degree);
        Ok(Self::from_binary_field_element(&elem))
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
#[allow(dead_code)]
pub struct SerializableExtensionFieldElement {
    #[serde(rename = "coefficients_base10")]
    pub coefficients_base10: Vec<String>,
    #[serde(rename = "coefficients_base16")]
    pub coefficients_base16: Vec<String>,
    #[serde(rename = "irreducible_coeffs_base10")]
    pub irreducible_coeffs_base10: Vec<String>,
    #[serde(rename = "modulus_base10")]
    pub modulus_base10: String,
}

impl SerializableExtensionFieldElement {
    /// Convert an ExtensionFieldElement to serializable form
    #[allow(dead_code)]
    pub fn from_extension_field_element(elem: &ExtensionFieldElement) -> Self {
        let coeffs = elem.coefficients();
        let irreducible_coeffs = elem.irreducible().coeffs();
        
        SerializableExtensionFieldElement {
            coefficients_base10: coeffs.iter().map(|c| c.value().to_base10()).collect(),
            coefficients_base16: coeffs.iter().map(|c| c.value().to_base16()).collect(),
            irreducible_coeffs_base10: irreducible_coeffs.iter()
                .map(|c| c.value().to_base10()).collect(),
            modulus_base10: elem.modulus().to_base10(),
        }
    }

    /// Convert to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    #[allow(dead_code)]
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
    Infinity,
    #[serde(rename = "point")]
    Point {
        x_base10: String,
        x_base16: String,
        x_base64: String,
        y_base10: String,
        y_base16: String,
        y_base64: String,
    },
}

impl SerializableECPoint {
    /// Convert an EllipticCurvePoint to serializable form
    pub fn from_ec_point(point: &EllipticCurvePoint<FieldElement>) -> Self {
        match point {
            EllipticCurvePoint::Infinity => SerializableECPoint::Infinity,
            EllipticCurvePoint::Point { x, y } => SerializableECPoint::Point {
                x_base10: x.value().to_base10(),
                x_base16: x.value().to_base16(),
                x_base64: x.value().to_base64(),
                y_base10: y.value().to_base10(),
                y_base16: y.value().to_base16(),
                y_base64: y.value().to_base64(),
            },
        }
    }

    /// Get compressed point format (x-coordinate only + sign bit)
    pub fn to_compressed(&self) -> Result<String, String> {
        match self {
            SerializableECPoint::Infinity => Ok("infinity".to_string()),
            SerializableECPoint::Point { x_base16, y_base10, .. } => {
                let y = BigUint::from_base10(y_base10)?;
                let prefix = if y.is_even() { "02" } else { "03" };
                Ok(format!("{}{}", prefix, x_base16))
            }
        }
    }

    /// Convert to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    #[allow(dead_code)]
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

/// Serializable representation of an elliptic curve over Fp
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableEllipticCurve {
    #[serde(rename = "curve_equation")]
    pub curve_equation: String, // "y^2 = x^3 + ax + b"
    pub a_base10: String,
    pub a_base16: String,
    pub b_base10: String,
    pub b_base16: String,
    pub modulus_base10: String,
    pub modulus_base16: String,
}

impl SerializableEllipticCurve {
    /// Create from curve parameters
    pub fn new(a: &FieldElement, b: &FieldElement) -> Self {
        SerializableEllipticCurve {
            curve_equation: "y^2 = x^3 + ax + b".to_string(),
            a_base10: a.value().to_base10(),
            a_base16: a.value().to_base16(),
            b_base10: b.value().to_base10(),
            b_base16: b.value().to_base16(),
            modulus_base10: a.modulus().to_base10(),
            modulus_base16: a.modulus().to_base16(),
        }
    }

    /// Convert to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    #[allow(dead_code)]
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
    Infinity,
    #[serde(rename = "point")]
    Point {
        x_base16: String,
        x_base64: String,
        y_base16: String,
        y_base64: String,
    },
}

impl SerializableBinaryECPoint {
    /// Convert a BinaryEllipticCurvePoint to serializable form
    pub fn from_binary_ec_point(point: &BinaryEllipticCurvePoint) -> Self {
        match point {
            BinaryEllipticCurvePoint::Infinity => SerializableBinaryECPoint::Infinity,
            BinaryEllipticCurvePoint::Point { x, y } => {
                let x_bytes = x.to_bytes();
                let y_bytes = y.to_bytes();
                
                SerializableBinaryECPoint::Point {
                    x_base16: bytes_to_hex(&x_bytes),
                    x_base64: base64::engine::general_purpose::STANDARD.encode(&x_bytes),
                    y_base16: bytes_to_hex(&y_bytes),
                    y_base64: base64::engine::general_purpose::STANDARD.encode(&y_bytes),
                }
            }
        }
    }

    /// Convert to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    #[allow(dead_code)]
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }
}

/// Serializable representation of a binary elliptic curve
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct SerializableBinaryEllipticCurve {
    #[serde(rename = "curve_equation")]
    pub curve_equation: String, // "y^2 + xy = x^3 + ax^2 + b"
    pub a_base16: String,
    pub b_base16: String,
    pub irreducible_base16: String,
    pub degree: usize,
}

impl SerializableBinaryEllipticCurve {
    /// Create from curve parameters
    #[allow(dead_code)]
    pub fn new(a: &BinaryFieldElement, b: &BinaryFieldElement) -> Self {
        SerializableBinaryEllipticCurve {
            curve_equation: "y^2 + xy = x^3 + ax^2 + b".to_string(),
            a_base16: bytes_to_hex(&a.to_bytes()),
            b_base16: bytes_to_hex(&b.to_bytes()),
            irreducible_base16: bytes_to_hex(a.irreducible()),
            degree: a.degree(),
        }
    }

    /// Convert to JSON string
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Create from JSON string
    #[allow(dead_code)]
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
        
        let ser = SerializableFieldElement::from_field_element(&elem);
        assert_eq!(ser.value_base10, "5");
        assert_eq!(ser.modulus_base10, "17");
        
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
        
        let ser = SerializableBinaryFieldElement::from_binary_field_element(&elem);
        
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
        
        let ser = SerializableECPoint::from_ec_point(&point);
        let json = ser.to_json().unwrap();
        let deser = SerializableECPoint::from_json(&json).unwrap();
        
        match (ser, deser) {
            (SerializableECPoint::Point { x_base10: x1, y_base10: y1, .. },
             SerializableECPoint::Point { x_base10: x2, y_base10: y2, .. }) => {
                assert_eq!(x1, x2);
                assert_eq!(y1, y2);
            }
            _ => panic!("Expected Point"),
        }
    }

    #[test]
    fn test_infinity_point_serialization() {
        let point = EllipticCurvePoint::<FieldElement>::Infinity;
        let ser = SerializableECPoint::from_ec_point(&point);
        
        let json = ser.to_json().unwrap();
        let deser = SerializableECPoint::from_json(&json).unwrap();
        
        assert!(matches!(deser, SerializableECPoint::Infinity));
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
}
