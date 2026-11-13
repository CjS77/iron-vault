// SPDX-License-Identifier: MPL-2.0
use proptest::prelude::*;

use super::*;

const R: &str = "[iron-vault:scrubbed]";

/// Scrubs `chunks` one after another with `patterns` and returns the output and match count, checking after every
/// chunk that fewer bytes are held than the longest pattern has
/// ([§11](../../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing): at most `n - 1`).
fn scrub_chunks(patterns: &[&[u8]], chunks: &[&[u8]]) -> (Vec<u8>, u64) {
    let longest = patterns.iter().map(|pattern| pattern.len()).max().unwrap_or(0);
    let mut scrubber = Scrubber::with_patterns(patterns.iter().copied());
    let mut out: Vec<u8> = chunks
        .iter()
        .flat_map(|chunk| {
            let released = scrubber.push(chunk);
            assert!(
                scrubber.held.len() < longest.max(1),
                "held {} of longest {longest}",
                scrubber.held.len()
            );
            released
        })
        .collect();
    let finished = scrubber.finish();
    out.extend(finished.tail);
    (out, finished.matches)
}

fn one_shot(patterns: &[&[u8]], input: &[u8]) -> (Vec<u8>, u64) {
    scrub_chunks(patterns, &[input])
}

/// Leftmost-longest scrubbing written independently of the scrubber: at each position, replace the longest pattern that
/// starts there, or else copy one byte.
fn naive(patterns: &[Vec<u8>], input: &[u8]) -> (Vec<u8>, u64) {
    let mut out = Vec::new();
    let mut matches = 0;
    let mut at = 0;
    while at < input.len() {
        let longest = patterns
            .iter()
            .filter(|pattern| !pattern.is_empty() && input[at..].starts_with(pattern))
            .map(Vec::len)
            .max();
        match longest {
            Some(len) => {
                out.extend_from_slice(R.as_bytes());
                matches += 1;
                at += len;
            }
            None => {
                out.push(input[at]);
                at += 1;
            }
        }
    }
    (out, matches)
}

fn scrubbed(patterns: &[&[u8]], input: &str) -> String {
    String::from_utf8(one_shot(patterns, input.as_bytes()).0).unwrap()
}

/// `input` cut at each of `cuts`, sorted and deduplicated, each taken modulo the input length plus one.
fn chunked(input: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let mut offsets: Vec<usize> = cuts.iter().map(|cut| cut % (input.len() + 1)).chain([0, input.len()]).collect();
    offsets.sort_unstable();
    offsets.dedup();
    offsets.windows(2).map(|pair| input[pair[0]..pair[1]].to_vec()).collect()
}

fn scrub_owned_chunks(patterns: &[Vec<u8>], chunks: &[Vec<u8>]) -> (Vec<u8>, u64) {
    let patterns: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();
    let chunks: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    scrub_chunks(&patterns, &chunks)
}

/// Bytes from a small alphabet, so random patterns overlap and random filler often begins one.
fn small_bytes(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop::sample::select(b"ab\nX".to_vec()), len)
}

/// Patterns, and an input built from filler with patterns planted between it.
fn patterns_and_input() -> impl Strategy<Value = (Vec<Vec<u8>>, Vec<u8>)> {
    let patterns = prop::collection::vec(small_bytes(1..6), 1..5);
    let pieces = prop::collection::vec((small_bytes(0..4), any::<prop::sample::Index>()), 0..8);
    (patterns, pieces).prop_map(|(patterns, pieces)| {
        let input = pieces
            .iter()
            .flat_map(|(filler, index)| filler.iter().chain(index.get(&patterns)).copied().collect::<Vec<u8>>())
            .collect();
        (patterns, input)
    })
}

proptest! {
    #[test]
    fn any_chunking_matches_one_shot((patterns, input) in patterns_and_input(), cuts in prop::collection::vec(any::<usize>(), 0..8)) {
        let whole = scrub_owned_chunks(&patterns, std::slice::from_ref(&input));
        prop_assert_eq!(scrub_owned_chunks(&patterns, &chunked(&input, &cuts)), whole);
    }

    #[test]
    fn any_chunking_matches_the_naive_scan((patterns, input) in patterns_and_input(), cuts in prop::collection::vec(any::<usize>(), 0..8)) {
        prop_assert_eq!(scrub_owned_chunks(&patterns, &chunked(&input, &cuts)), naive(&patterns, &input));
    }

    #[test]
    fn one_byte_chunks_match_one_shot((patterns, input) in patterns_and_input()) {
        let whole = scrub_owned_chunks(&patterns, std::slice::from_ref(&input));
        let bytes: Vec<Vec<u8>> = input.iter().map(|byte| vec![*byte]).collect();
        prop_assert_eq!(scrub_owned_chunks(&patterns, &bytes), whole);
    }

    #[test]
    fn input_without_a_pattern_is_unchanged(input in prop::collection::vec(any::<u8>(), 0..64)) {
        let pattern: &[u8] = b"\xffsk-unseen\xff";
        prop_assume!(!input.windows(pattern.len()).any(|window| window == pattern));
        prop_assert_eq!(one_shot(&[pattern], &input), (input, 0));
    }
}

#[test]
fn a_split_at_every_offset_matches_one_shot() {
    let patterns: &[&[u8]] = &[b"Basic dXNlcjpwYXNz", b"dXNlcjpwYXNz", b"pass", b"ab", b"abc"];
    let input = b"ab Basic dXNlcjpwYXNz abcpassab\ndata: dXNlcjpwYXNzab";
    let whole = one_shot(patterns, input);
    assert_eq!(whole.1, 7);
    (0..=input.len()).for_each(|cut| {
        let (head, tail) = input.split_at(cut);
        assert_eq!(scrub_chunks(patterns, &[head, tail]), whole, "split at {cut}");
    });
}

#[test]
fn longest_of_nested_patterns_wins() {
    assert_eq!(scrubbed(&[b"ab", b"abc"], "xabcx abx"), format!("x{R}x {R}x"));
    assert_eq!(
        scrubbed(&[b"X", b"Basic X"], "Authorization: Basic X"),
        format!("Authorization: {R}")
    );
}

#[test]
fn leftmost_match_wins_over_a_longer_later_one() {
    assert_eq!(scrubbed(&[b"ab", b"bcd"], "abcd"), format!("{R}cd"));
}

#[test]
fn adjacent_matches_are_each_replaced() {
    let (out, matches) = one_shot(&[b"ab", b"cd"], b"abcdab");
    assert_eq!(String::from_utf8(out).unwrap(), format!("{R}{R}{R}"));
    assert_eq!(matches, 3);
}

#[test]
fn patterns_at_the_very_start_and_end_are_replaced() {
    assert_eq!(scrubbed(&[b"key"], "key middle key"), format!("{R} middle {R}"));
    assert_eq!(scrubbed(&[b"key"], "key"), R);
}

#[test]
fn a_match_that_could_still_grow_is_held_until_the_end() {
    let mut scrubber = Scrubber::with_patterns([b"ab".as_slice(), b"abc"]);
    assert_eq!(&scrubber.push(b"x ab")[..], b"x ");
    assert_eq!(&scrubber.push(b"c")[..], R.as_bytes());
    assert_eq!(&scrubber.push(b" ab")[..], b" ");
    assert_eq!(scrubber.matches(), 1);
    let finished = scrubber.finish();
    assert_eq!(&finished.tail[..], R.as_bytes());
    assert_eq!(finished.matches, 2);
}

#[test]
fn a_whole_sse_event_is_released_at_once() {
    let mut scrubber = Scrubber::with_patterns([b"data-secret".as_slice(), b"hi there"]);
    assert_eq!(&scrubber.push(b"data: hi\n\n")[..], b"data: hi\n\n");
    assert_eq!(&scrubber.finish().tail[..], b"");
}

#[test]
fn only_the_possible_prefix_is_held() {
    let mut scrubber = Scrubber::with_patterns([b"secret".as_slice()]);
    assert_eq!(&scrubber.push(b"a secre")[..], b"a ");
    assert_eq!(&scrubber.push(b"tive")[..], format!("{R}ive").as_bytes());
    assert_eq!(&scrubber.push(b" sec")[..], b" ");
    assert_eq!(&scrubber.push(b"ond")[..], b"second");
    assert_eq!(scrubber.matches(), 1);
}

#[test]
fn case_is_never_folded() {
    assert_eq!(scrubbed(&[b"abc"], "ABC aBc abc"), format!("ABC aBc {R}"));
}

#[test]
fn no_patterns_passes_everything_through() {
    assert_eq!(scrubbed(&[], "anything\n"), "anything\n");
}

mod headers {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    use super::*;

    const SECRET: &[u8] = b"sk-secret-key-123";
    // The patterns for a second secret, `sk/secret+key=123`, in the URL-encoded forms the pattern set holds in both hex cases.
    const ENCODED_UPPER: &[u8] = b"sk%2Fsecret%2Bkey%3D123";
    const ENCODED_LOWER: &[u8] = b"sk%2fsecret%2bkey%3d123";

    fn scrubbed(headers: &mut HeaderMap) -> u64 {
        scrub_header_values(headers, || Scrubber::with_patterns([SECRET, ENCODED_UPPER, ENCODED_LOWER]))
    }

    fn map(pairs: &[(&'static str, &[u8])]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (HeaderName::from_static(name), HeaderValue::from_bytes(value).unwrap()))
            .fold(HeaderMap::new(), |mut headers, (name, value)| {
                headers.append(name, value);
                headers
            })
    }

    #[test]
    fn replaces_secret_in_custom_www_authenticate_and_location() {
        let mut headers = map(&[
            ("x-debug", b"key=sk-secret-key-123"),
            ("www-authenticate", b"Bearer error_description=\"bad sk-secret-key-123\""),
            ("location", b"/next?k=sk%2Fsecret%2Bkey%3D123&a=1"),
            ("x-redirect", b"/next?k=sk%2fsecret%2bkey%3d123"),
            ("content-type", b"application/json"),
        ]);
        assert_eq!(scrubbed(&mut headers), 4);
        assert_eq!(headers["x-debug"], format!("key={R}").as_str());
        assert_eq!(
            headers["www-authenticate"],
            format!("Bearer error_description=\"bad {R}\"").as_str()
        );
        assert_eq!(headers["location"], format!("/next?k={R}&a=1").as_str());
        assert_eq!(headers["x-redirect"], format!("/next?k={R}").as_str());
        assert_eq!(headers["content-type"], "application/json");
    }

    #[test]
    fn unmatched_headers_are_unchanged() {
        let mut headers = map(&[("x-a", b"one"), ("x-b", b"sk-secret")]);
        let before = headers.clone();
        assert_eq!(scrubbed(&mut headers), 0);
        assert_eq!(headers, before);
    }

    #[test]
    fn repeated_headers_are_each_scrubbed() {
        let mut headers = map(&[
            ("x-echo", b"sk-secret-key-123"),
            ("x-echo", b"ok"),
            ("x-echo", b"a sk-secret-key-123"),
        ]);
        assert_eq!(scrubbed(&mut headers), 2);
        let values: Vec<&[u8]> = headers.get_all("x-echo").iter().map(HeaderValue::as_bytes).collect();
        assert_eq!(values, [R.as_bytes(), b"ok", format!("a {R}").as_bytes()]);
    }

    #[test]
    fn counts_matches_not_values() {
        let mut headers = map(&[("x-echo", b"sk-secret-key-123 sk-secret-key-123"), ("x-one", b"sk-secret-key-123")]);
        assert_eq!(scrubbed(&mut headers), 3);
        assert_eq!(headers["x-echo"], format!("{R} {R}").as_str());
    }

    #[test]
    fn non_utf8_value_is_scrubbed_as_bytes() {
        let mut headers = map(&[("x-raw", b"\xff\xfesk-secret-key-123\xfd")]);
        assert_eq!(scrubbed(&mut headers), 1);
        assert_eq!(
            headers["x-raw"].as_bytes(),
            [b"\xff\xfe".as_slice(), R.as_bytes(), b"\xfd"].concat()
        );
    }
}
