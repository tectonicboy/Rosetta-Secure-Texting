#pragma once

#include "wx/wx.h"

class cMain : public wxFrame
{
public:
     cMain();
    ~cMain();

    wxButton *btn_login = NULL;
    wxButton *btn_login_GO = NULL;
    wxButton *btn_login_BACK = NULL;
    wxButton *btn_reg = NULL;
    wxButton *btn_reg_create = NULL;
    wxButton *btn_reg_back = NULL;
    
    //wxTextCtrl *ROSETTA_LABEL = NULL;
    
    wxListBox *MSG_entries = NULL;
    wxTextCtrl* ROSETTA_LABEL = NULL;
    
    
    /* Events have types. wxCommandEvent is the type for a button click. */
    /* which in simple terms is the "do something" event.                */
    void OnButtonClicked(wxCommandEvent &evt);
    
    //(void(cMain::*)(wxCommandEvent)) pointer=&A::f;
    
    wxDECLARE_EVENT_TABLE();

};
