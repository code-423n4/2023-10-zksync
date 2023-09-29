# Sorting and deduplicating

We have four circuits, that receive some queue of elements and do sorting and deduplicating: [SortDecommitments](../SortDecommitments%208b6c67c18d4b456a835ddbe87fd0175e.md), [StorageSorter](../StorageSorter%20611de56e0cfc49e8a9831e4b0d1b3cdd.md), [EventsSorter](../LogSorter%204a0fa92896c448f5995ffc94bee075bc.md) and [L1MessageSorter](../LogSorter%204a0fa92896c448f5995ffc94bee075bc.md).

The main scenario is the following: we have an input queue of elements, that 1) could be compared between each other,