from rest_framework.pagination import PageNumberPagination


class SentinelPagination(PageNumberPagination):
    """CONTRACTS section 2: {count, next, previous, results}, ?page=&page_size= (max 100)."""

    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100
