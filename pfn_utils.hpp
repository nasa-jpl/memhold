
#pragma once

#include <cstdint>

#include <vector>

#define PAGE_SIZE (4 * 1024)

// MAX_PFN = 2^32 / PAGE_SIZE
#define MAX_PFN (0x100000)

#define PFN_VALID(pfn) ((pfn) >= 0 && (pfn) < MAX_PFN)

// Note: See pfn_utils.cpp for documentation

std::vector<int64_t> read_pfn_list(std::ifstream& pfn_list_f);

std::vector<int64_t> find_inuse_pfns(const std::vector<int64_t>& pfn_list);

int64_t pfn_for_pagemap_entry(const uint64_t pm_entry);

