/*
**	Command & Conquer Generals(tm)
**	Copyright 2025 Electronic Arts Inc.
**
**	This program is free software: you can redistribute it and/or modify
**	it under the terms of the GNU General Public License as published by
**	the Free Software Foundation, either version 3 of the License, or
**	(at your option) any later version.
**
**	This program is distributed in the hope that it will be useful,
**	but WITHOUT ANY WARRANTY; without even the implied warranty of
**	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**	GNU General Public License for more details.
**
**	You should have received a copy of the GNU General Public License
**	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

////////////////////////////////////////////////////////////////////////////////
//																																						//
//  (c) 2001-2003 Electronic Arts Inc.																				//
//																																						//
////////////////////////////////////////////////////////////////////////////////

// FILE: LookAtXlat.h ///////////////////////////////////////////////////////////
// Author: Steven Johnson, Dec 2001

#pragma once

#include "GameClient/InGameUI.h"

//-----------------------------------------------------------------------------
// TheSuperHackers @feature The Screen Edge Scrolling can now be enabled or
// disabled depending on the App being Windowed or Fullscreen.
typedef UnsignedInt ScreenEdgeScrollMode;
enum ScreenEdgeScrollMode_ CPP_11(: ScreenEdgeScrollMode)
{
	ScreenEdgeScrollMode_EnabledInWindowedApp = 1<<0, // Scroll when touching the edge while the app is windowed
	ScreenEdgeScrollMode_EnabledInFullscreenApp = 1<<1, // Scroll when touching the edge while the app is fullscreen

	ScreenEdgeScrollMode_Default = ScreenEdgeScrollMode_EnabledInFullscreenApp, // Default based on original game behavior
};

//-----------------------------------------------------------------------------
class LookAtTranslator : public GameMessageTranslator
{
public:
	LookAtTranslator();
	~LookAtTranslator();

	virtual GameMessageDisposition translateGameMessage(const GameMessage *msg);
	virtual const ICoord2D* getRMBScrollAnchor(void); // get m_anchor ICoord2D if we're RMB scrolling
	Bool hasMouseMovedRecently( void );
	void setCurrentPos( const ICoord2D& pos );
	void setScreenEdgeScrollMode(ScreenEdgeScrollMode mode);

	void resetModes(); //Used when disabling input, so when we reenable it we aren't stuck in a mode.

private:
	enum
	{
		MAX_VIEW_LOCS = 8
	};
	enum ScrollType
	{
		SCROLL_NONE = 0,
		SCROLL_RMB,
		SCROLL_KEY,
		SCROLL_SCREENEDGE
	};
	ICoord2D m_anchor;
	ICoord2D m_originalAnchor;
	ICoord2D m_currentPos;
	Bool m_isScrolling;				// set to true if we are in the act of RMB scrolling
	Bool m_isRotating;					// set to true if we are in the act of MMB rotating
	Bool m_isPitching;					// set to true if we are in the act of ALT pitch rotation
	Bool m_isChangingFOV;			// set to true if we are in the act of changing the field of view
	UnsignedInt m_timestamp;				// set when button goes down
	DrawableID m_lastPlaneID;
	ViewLocation m_viewLocation[ MAX_VIEW_LOCS ];
	ScrollType m_scrollType;
	ScreenEdgeScrollMode m_screenEdgeScrollMode;
	UnsignedInt m_lastMouseMoveFrame;

	void setScrolling( ScrollType scrollType );
	void stopScrolling( void );
	Bool canScrollAtScreenEdge() const;
};

extern LookAtTranslator *TheLookAtTranslator;
