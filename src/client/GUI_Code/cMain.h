#pragma once

#include "wx/wx.h"

class cMain : public wxFrame
{
public:
     cMain();
    ~cMain();

    wxButton* btn_login         = NULL;
    wxButton* btn_login_GO      = NULL;
    wxButton* btn_login_BACK    = NULL;
    wxButton* btn_reg           = NULL;
    wxButton* btn_reg_GO        = NULL;
    wxButton* btn_reg_BACK      = NULL;

    wxButton* btn_quit          = NULL;

    wxButton* btn_makeroom      = NULL;
    wxButton* btn_joinroom      = NULL;
    wxButton* btn_makeroom_GO   = NULL;
    wxButton* btn_joinroom_GO   = NULL;
    wxButton* btn_makeroom_BACK = NULL;
    wxButton* btn_joinroom_BACK = NULL;

    wxButton* btn_closeyourroom = NULL;
    wxButton* btn_leavetheroom  = NULL;
    
    wxListBox*  MSG_entries = NULL;

    wxTextCtrl* ROSETTA_LABEL  = NULL;
    wxTextCtrl* password_input = NULL;
    wxTextCtrl* roomid_input   = NULL;
    wxTextCtrl* userid_input   = NULL;
    wxTextCtrl* info_msg_box   = NULL;
    
    /* Events have types. wxCommandEvent is the type for a button click. */
    /* which in simple terms is the "do something" event.                */
    void BtnClickLogin(wxCommandEvent &evt);
    void BtnClickRegister(wxCommandEvent &evt);
    void BtnClickLoginGo(wxCommandEvent &evt);
    void BtnClickLoginBack(wxCommandEvent &evt);
    void BtnClickRegGo(wxCommandEvent &evt);
    void BtnClickRegBack(wxCommandEvent &evt);

    void BtnClickQuit(wxCommandEvent &evt);

    void BtnClickMakeRoom(wxCommandEvent &evt);
    void BtnClickJoinRoom(wxCommandEvent &evt);
    void BtnClickJoinRoomGo(wxCommandEvent &evt);
    void BtnClickJoinRoomBack(wxCommandEvent &evt);
    void BtnClickMakeRoomGo(wxCommandEvent &evt);
    void BtnClickMakeRoomBack(wxCommandEvent &evt);

    void BtnClickCloseYourRoom(wxCommandEvent &evt);
    void BtnClickLeaveTheRoom(wxCommandEvent &evt);


    wxDECLARE_EVENT_TABLE();

};
