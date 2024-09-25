use std::{collections::HashMap, sync::Arc};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use cel_interpreter::Value;

// Convert a `Vec<HeaderValue>` to a [Value].
// Single-element vectors are converted to the single element.
fn header_values_to_value(hvs: Vec<HeaderValue>) -> Value {
    fn to_cel_value(hv: HeaderValue) -> Value {
        match hv.to_str() {
            Ok(s) => Value::String(Arc::new(s.to_owned())),
            Err(_) => Value::Bytes(Arc::new(hv.as_bytes().to_vec())),
        }
    }

    let mut vs = hvs.into_iter().map(to_cel_value).collect::<Vec<_>>();
    if vs.len() == 1 {
        vs.pop().unwrap()
    } else {
        Value::List(Arc::new(vs))
    }
}

pub fn parse_headers(header_map: HeaderMap<HeaderValue>) -> Value {
    let mut out: HashMap<String, Value> = HashMap::new();

    let last = header_map.into_iter().fold(
        None,
        |prev: Option<(HeaderName, Vec<HeaderValue>)>, (hn, hv)| {
            if let Some(hn) = hn {
                // new header name, pop what's in the accumulator
                if let Some((prev_hn, prev_hvs)) = prev {
                    out.insert(
                        prev_hn.as_str().to_owned(),
                        header_values_to_value(prev_hvs),
                    );
                }

                Some((hn, vec![hv]))
            } else {
                // same header, extend accumulator
                let (prev_hn, mut prev_hvs) = prev.expect("accumulator must be some");
                prev_hvs.push(hv);

                Some((prev_hn, prev_hvs))
            }
        },
    );
    if let Some((hn, hv)) = last {
        out.insert(hn.as_str().to_owned(), header_values_to_value(hv));
    }

    out.into()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use super::parse_headers;
    use axum::http::{HeaderMap, HeaderValue};
    use cel_interpreter::{objects::Map, Value};

    #[test]
    fn empty() {
        assert_eq!(
            Value::Map(Map {
                map: Arc::new(HashMap::new())
            }),
            parse_headers(HeaderMap::new())
        );
    }

    #[test]
    fn string_and_unicode() {
        let mut hm = HeaderMap::new();
        hm.insert("a", HeaderValue::from_static("b"));
        hm.insert(
            "foo",
            HeaderValue::from_bytes(b"bar\xc5\xc4\xd6foo")
                .expect("unable to construct HeaderValue"),
        );

        assert_eq!(
            Value::Map(Map {
                map: Arc::new(HashMap::from_iter([
                    (
                        cel_interpreter::objects::Key::String(Arc::new("a".to_string())),
                        Value::String(Arc::new("b".to_string()))
                    ),
                    (
                        cel_interpreter::objects::Key::String(Arc::new("foo".to_string())),
                        Value::Bytes(Arc::new(b"bar\xc5\xc4\xd6foo".to_vec()))
                    )
                ]))
            }),
            parse_headers(hm)
        );
    }

    #[test]
    fn multi_value() {
        let mut hm = HeaderMap::new();
        hm.insert("a", HeaderValue::from_static("b"));
        assert!(hm.append("a", HeaderValue::from_static("c")));
        hm.insert(
            "foo",
            HeaderValue::from_bytes(b"bar\xc5\xc4\xd6foo")
                .expect("unable to construct HeaderValue"),
        );

        assert_eq!(
            Value::Map(Map {
                map: Arc::new(HashMap::from_iter([
                    (
                        cel_interpreter::objects::Key::String(Arc::new("a".to_string())),
                        Value::List(Arc::new(vec![
                            Value::String(Arc::new("b".to_string())),
                            Value::String(Arc::new("c".to_string()))
                        ]))
                    ),
                    (
                        cel_interpreter::objects::Key::String(Arc::new("foo".to_string())),
                        Value::Bytes(Arc::new(b"bar\xc5\xc4\xd6foo".to_vec()))
                    )
                ]))
            }),
            parse_headers(hm)
        );
    }
}
