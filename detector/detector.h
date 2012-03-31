/*
 * =====================================================================================
 *
 *       Filename:  detector.h
 *
 *    Description:	Return-Oriented Rootkit - TEMU plugin
 *
 *        Version:  1.0
 *        Created:  03/31/2012 07:00:40 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:	Do Hoang Nhat Huy
 *        Company:
 *
 * =====================================================================================
 */

#ifndef  DETECTOR_INC
#define  DETECTOR_INC

//! This structure is copied from Hookfinder and can be customized further.
typedef struct {
	// Id of the caller
	uint32_t caller;
	// Id of the callee
	uint32_t callee;
	// EIP register
	uint32_t eip;
	// Still trying to figure out what it is.
	// uint32_t depend_id;
} taint_record_t;

#endif   /* ----- #ifndef DETECTOR_INC  ----- */

