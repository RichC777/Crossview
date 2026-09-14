#pragma once
#include "offsets.h"
#include "../shared/CrossViewShared.h"

NTSTATUS CvRunScan(ULONG Modules, CV_SCAN_RESULT *Result, const CV_OFFSETS *Off);
