use proptest::prelude::*;

use super::*;

const R: &str = "[iron-vault:scrubbed]";

/// The output and match count of scrubbing `chunks` in turn with `patterns`, checking after every chunk that fewer
/// bytes are held than the longest pattern has (§3.8: at most `n - 1`).
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
    out.extend(scrubber.finish());
    (out, scrubber.matches())
}

fn one_shot(patterns: &[&[u8]], input: &[u8]) -> (Vec<u8>, u64) {
    scrub_chunks(patterns, &[input])
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
    assert_eq!(&scrubber.finish()[..], R.as_bytes());
    assert_eq!(scrubber.matches(), 2);
}

#[test]
fn a_whole_sse_event_is_released_at_once() {
    let mut scrubber = Scrubber::with_patterns([b"data-secret".as_slice(), b"hi there"]);
    assert_eq!(&scrubber.push(b"data: hi\n\n")[..], b"data: hi\n\n");
    assert_eq!(&scrubber.finish()[..], b"");
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
