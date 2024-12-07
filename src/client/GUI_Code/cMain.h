#pragma once

#include "wx/wx.h"

class cMain : public wxFrame
{
public:
     cMain();
    ~cMain();

    wxButton *btn_login      = NULL;
    wxButton *btn_login_GO   = NULL;
    wxButton *btn_login_BACK = NULL;
    wxButton *btn_reg        = NULL;
    wxButton *btn_reg_GO     = NULL;
    wxButton *btn_reg_BACK   = NULL;
    
    //wxTextCtrl *ROSETTA_LABEL = NULL;
    
    wxListBox  *MSG_entries    = NULL;
    wxTextCtrl *ROSETTA_LABEL  = NULL;
    wxTextCtrl *password_input = NULL;
    wxTextCtrl *err_msg_box    = NULL;
    
    /* Events have types. wxCommandEvent is the type for a button click. */
    /* which in simple terms is the "do something" event.                */
    void BtnClickLogin(wxCommandEvent &evt);
    void BtnClickRegister(wxCommandEvent &evt);
    void BtnClickLoginGo(wxCommandEvent &evt);
    void BtnClickLoginBack(wxCommandEvent &evt);
    void BtnClickRegGo(wxCommandEvent &evt);
    void BtnClickRegBack(wxCommandEvent &evt);


    wxDECLARE_EVENT_TABLE();

};
