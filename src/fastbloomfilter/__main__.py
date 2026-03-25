from fastbloomfilter.bloom import BloomFilter


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="fastBloomFilter CLI")
    parser.add_argument("filename", nargs="?", help="Filter file to load/create")
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=(1024**2) * 128,
        help="Array size in bytes (default: 128MB)",
    )
    parser.add_argument(
        "--slices",
        type=int,
        default=10,
        help="Number of hash slices (default: 10)",
    )
    parser.add_argument(
        "--mmap",
        action="store_true",
        help="Use memory mapping",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print statistics",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Print full info",
    )

    args = parser.parse_args()

    bf = BloomFilter(
        array_size=args.size,
        slices=args.slices,
        filename=args.filename,
        use_mmap=args.mmap,
    )

    if args.stats:
        bf.stat()

    if args.info:
        bf.info()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
