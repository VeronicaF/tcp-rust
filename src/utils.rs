/// check if x is in `(start, end]` with wraparound
pub fn is_in_range_wrapped(start: u32, end: u32, x: u32) -> bool {
    if start < end {
        start < x && x <= end
    } else {
        start < x || x <= end
    }
}

/// check if x is in `[start, end)` with wraparound
pub fn is_in_range_wrapped1(start: u32, end: u32, x: u32) -> bool {
    if start < end {
        start <= x && x < end
    } else {
        start <= x || x < end
    }
}

/// check if x is in `[start, end]` with wraparound
pub fn is_in_range_wrapped2(start: u32, end: u32, x: u32) -> bool {
    if start < end {
        start <= x && x <= end
    } else {
        start <= x || x <= end
    }
}

/// check if x is in `(start, end)` with wraparound
pub fn is_in_range_wrapped3(start: u32, end: u32, x: u32) -> bool {
    if start < end {
        start < x && x < end
    } else {
        start < x || x < end
    }
}
