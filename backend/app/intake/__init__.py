"""Intake — turn a user-named source into a directory, enumerate it, gate it.

The three stages of SPEC.md §4 steps 2-5, deliberately kept apart from the
collectors: nothing here reads file *contents*, and nothing here decides what a
file means. Staging produces a directory, the surface scan produces a list of
paths, and the selection gate records which of those paths the user approved.
"""
