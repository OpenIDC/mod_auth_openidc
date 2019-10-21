/*
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */
/**
 * \file
 * \brief
 * Function to retrieve the version of CJOSE
 */

#ifndef _CJOSE_VERSION_H_
#define _CJOSE_VERSION_H_

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * The declaration version of CJOSE. This identifies
 * the version the header files were compiled for.
 */
#define CJOSE_VERSION "@PACKAGE_VERSION@"

/**
 * Retrieves the implementation version of CJOSE.
 *
 * \returns the implementation version number.
 */
const char *cjose_version();

#ifdef __cplusplus
}
#endif

#endif  // _CJOSE_VERSION_H_
