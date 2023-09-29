# Sorting and deduplicating

We have four circuits, that receive some queue of elements and do sorting and deduplicating: [SortDecommitments](../SortDecommitments.md), [StorageSorter](../StorageSorter.md), [EventsSorter](../LogSorter.md) and [L1MessageSorter](../LogSorter.md).

The main scenario is the following: we have an input queue of elements, that 1) could be compared between each other,
