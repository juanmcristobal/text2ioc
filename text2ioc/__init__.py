"""Top-level package for text2ioc."""

from text2ioc.ioc import (_find_invalid_occurrences, _is_unlikely_linux_path,
                          extract_iocs, get_tld_set_from_public_suffix_list,
                          post_filter_false_positives)

__author__ = "Juan Manuel Cristóbal Moreno"
__email__ = "juanmcristobal@gmail.com"
__version__ = "0.1.1"

__all__ = [
    "_find_invalid_occurrences",
    "_is_unlikely_linux_path",
    "extract_iocs",
    "get_tld_set_from_public_suffix_list",
    "post_filter_false_positives",
]
