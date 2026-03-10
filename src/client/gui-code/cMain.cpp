/* This define is used in the high-level C client communications engine
 * to distinguish between the client having been started with this GUI app
 * and it having been started with the Rosetta Test Framework, which would not
 * have a GUI to display messages on.
 */
#define USE_WX_GUI

#include "cMain.h"
#include "../network-code/client-primary-functions.h"

/* Implement what the Event Table is.
 *
 * Parm 1 - the class it is producing the events for.
 * Parm 2 - it also requires the base class that parm 1 inherited from.
 */
BEGIN_EVENT_TABLE(cMain, wxFrame)
    EVT_BUTTON(10001, cMain::BtnClickLogin          )
    EVT_BUTTON(10002, cMain::BtnClickRegister       )
    EVT_BUTTON(10003, cMain::BtnClickLoginGo        )
    EVT_BUTTON(10004, cMain::BtnClickLoginBack      )
    EVT_BUTTON(10005, cMain::BtnClickRegGo          )
    EVT_BUTTON(10006, cMain::BtnClickRegBack        )
    EVT_BUTTON(10007, cMain::BtnClickQuit           )
    EVT_BUTTON(10008, cMain::BtnClickMakeRoom       )
    EVT_BUTTON(10009, cMain::BtnClickJoinRoom       )
    EVT_BUTTON(10010, cMain::BtnClickJoinRoomGo     )
    EVT_BUTTON(10011, cMain::BtnClickJoinRoomBack   )
    EVT_BUTTON(10012, cMain::BtnClickMakeRoomGo     )
    EVT_BUTTON(10013, cMain::BtnClickMakeRoomBack   )
    EVT_BUTTON(10014, cMain::BtnClickCloseYourRoom  )
    EVT_BUTTON(10015, cMain::BtnClickLeaveTheRoom   )
	EVT_BUTTON(10016, cMain::BtnClickSendMsg        )
END_EVENT_TABLE()

int8_t userid[SMALL_FIELD_LEN];
int userid_len;

/* This gets assigned to the "this" pointer in the cMain class constructor,
 * which means we get a pointer to whichever instantiated object of cMain
 * this constructor ran FOR THE LAST TIME for. But since in wxWidgets, we
 * only have 1 object of the cMain class, this means that we simply get a
 * pointer to "the cMain object", allowing us to access its public member
 * variables, aka msg_entries. A completely normal C function pointer is
 * then assigned to a statically declared function here which accesses
 * that global cMain object's msg_entries public member variable. This is how
 * we obtain a workaround that lets the C client communications engine deliver
 * received messages and display them on the wxWidgets C++ GUI. I hate OOP :-)
 */
static cMain *g_instance = nullptr;

void display_gui_message(char* message_line){
	printf("[WARNING] Called the disaply reveied msg on GUI function.\n" );
    g_instance->msg_entries->AppendText(wxString::FromUTF8(message_line));
    g_instance->msg_entries->AppendText("\n");
 	return;
}

/* Constructor - uses constructor of wxFrame with parameters. */
cMain::cMain() : wxFrame(
                   nullptr
                  ,wxID_ANY            /* Give it any ID, doesn't matter     */
                  ,"Rosetta"           /* Title of the window                */
                  ,wxPoint(0, 0)       /* X,Y where to spawn - top left      */
                  ,wxSize(1920, 1080)  /* Size of the window in pixels       */
                 )
{
    g_instance = this;
	display_received_msg = display_gui_message;

	/* Construct the button member variable. */
    btn_login = new wxButton(
         this              /* Parent of the button - this window class        */
        ,10001             /* Match the ID we specified in the Event Table.   */
        ,"Login"           /* Label of the button                             */
        ,wxPoint(850, 600) /* X,Y spawn relative to top left corner of parent */
        ,wxSize(200, 50)   /* Width and height in pixels                      */
    );

    btn_reg = new wxButton
      (this, 10002, "Register", wxPoint(850, 660), wxSize(200, 50));

    btn_login_GO = new wxButton
      (this, 10003, "Go", wxPoint(850, 600), wxSize(200, 50));

    btn_login_BACK = new wxButton
	  (this, 10004, "Back", wxPoint(850, 660), wxSize(200, 50));

    btn_reg_GO = new wxButton
	  (this, 10005, "Go", wxPoint(850, 600), wxSize(200, 50));

    btn_reg_BACK = new wxButton
	  (this, 10006, "Back", wxPoint(850, 660), wxSize(200, 50));

    btn_quit = new wxButton
	  (this, 10007, "Quit Rosetta", wxPoint(850, 720), wxSize(200, 50));

    btn_makeroom = new wxButton
	  (this, 10008, "Create a chat room", wxPoint(850, 600), wxSize(200, 50));

    btn_joinroom = new wxButton
	  (this, 10009, "Join a chat room", wxPoint(850, 660), wxSize(200, 50));

    btn_joinroom_GO = new wxButton
	  (this, 10010, "Go", wxPoint(850, 600), wxSize(200, 50));

    btn_joinroom_BACK = new wxButton
	  (this, 10011, "Back", wxPoint(850, 660), wxSize(200, 50));

    btn_makeroom_GO = new wxButton
	  (this, 10012, "Go", wxPoint(850, 600), wxSize(200, 50));

    btn_makeroom_BACK = new wxButton
	  (this, 10013, "Back", wxPoint(850, 660), wxSize(200, 50));

    btn_closeyourroom = new wxButton
	  (this, 10014, "Close the chat room", wxPoint(850, 900), wxSize(200, 50));

    btn_leavetheroom = new wxButton
	  (this, 10015, "Leave the chat room", wxPoint(850, 900), wxSize(200, 50));

    btn_send_msg = new wxButton
	  (this, 10016, "Send", wxPoint(1660, 810), wxSize(50, 50));

    btn_login_GO->Hide();
    btn_login_BACK->Hide();
    btn_reg_GO->Hide();
    btn_reg_BACK->Hide();
    btn_makeroom->Hide();
    btn_joinroom->Hide();
    btn_makeroom_GO->Hide();
    btn_joinroom_GO->Hide();
    btn_makeroom_BACK->Hide();
    btn_joinroom_BACK->Hide();
    btn_closeyourroom->Hide();
    btn_leavetheroom->Hide();
	btn_send_msg->Hide();

    password_input = new wxTextCtrl
	  (this, wxID_ANY, "", wxPoint(850, 750), wxSize(200, 50), wxTE_PASSWORD);

    password_input->SetHint("Your password...");

    roomid_input = new wxTextCtrl
	  (this, wxID_ANY, "", wxPoint(850, 750), wxSize(300, 50));

    roomid_input->SetHint("Chat room's name...");

    userid_input = new wxTextCtrl
	  (this, wxID_ANY, "", wxPoint(850, 810), wxSize(300, 50));

    userid_input->SetHint("Your codename for this chatroom...");

    usermsg_input = new wxTextCtrl
	  (this, wxID_ANY, "", wxPoint(725, 810), wxSize(800, 50));

    usermsg_input->SetHint("Your message...  (limit: 1024 characters)");

    info_msg_box = new wxTextCtrl
	  (this, wxID_ANY, "",
       wxPoint(725, 880), wxSize(500, 150), wxTE_READONLY | wxTE_MULTILINE);

    msg_entries = new wxTextCtrl
	  (this, wxID_ANY, "",
	   wxPoint(725, 400), wxSize(800, 400), wxTE_READONLY | wxTE_MULTILINE);

	usermsg_input->Hide();
	msg_entries->Hide();
    password_input->Hide();
    info_msg_box->Hide();
    roomid_input->Hide();
    userid_input->Hide();

    /* Similarly construct the rest of the member variables. */

    /*
    ROSETTA_LABEL = new wxTextCtrl(
         this
        ,wxID_ANY
        ,""
        ,wxPoint(10, 70)
        ,wxSize(1500, 300)
    );
    */

    ROSETTA_LABEL = new wxTextCtrl(
        this
        ,wxID_ANY
        ,"RRRRRRRRRRRRRRRRR         OOOOOOOOO         SSSSSSSSSSSSSSS  EEEEEEEEEEEEEEEEEEEEEE TTTTTTTTTTTTTTTTTTTTTTT TTTTTTTTTTTTTTTTTTTTTTT          AAA               \n"
         "R::::::::::::::::R      OO:::::::::OO     SS:::::::::::::::S E::::::::::::::::::::E T:::::::::::::::::::::T T:::::::::::::::::::::T         A:::A              \n"
         "R::::::RRRRRR:::::R   OO:::::::::::::OO  S:::::SSSSSS::::::S E::::::::::::::::::::E T:::::::::::::::::::::T T:::::::::::::::::::::T        A:::::A             \n"
         "RR:::::R     R:::::R O:::::::OOO:::::::O S:::::S     SSSSSSS EE::::::EEEEEEEEE::::E T:::::TT:::::::TT:::::T T:::::TT:::::::TT:::::T       A:::::::A            \n"
         "  R::::R     R:::::R O::::::O   O::::::O S:::::S               E:::::E       EEEEEE TTTTTT  T:::::T  TTTTTT TTTTTT  T:::::T  TTTTTT      A:::::::::A           \n"
         "  R::::R     R:::::R O:::::O     O:::::O S:::::S               E:::::E                      T:::::T                 T:::::T             A:::::A:::::A          \n"
         "  R::::RRRRRR:::::R  O:::::O     O:::::O  S::::SSSS            E::::::EEEEEEEEEE            T:::::T                 T:::::T            A:::::A A:::::A         \n"
         "  R:::::::::::::RR   O:::::O     O:::::O   SS::::::SSSSS       E:::::::::::::::E            T:::::T                 T:::::T           A:::::A   A:::::A        \n"
         "  R::::RRRRRR:::::R  O:::::O     O:::::O     SSS::::::::SS     E:::::::::::::::E            T:::::T                 T:::::T          A:::::A     A:::::A       \n"
         "  R::::R     R:::::R O:::::O     O:::::O        SSSSSS::::S    E::::::EEEEEEEEEE            T:::::T                 T:::::T         A:::::AAAAAAAAA:::::A      \n"
         "  R::::R     R:::::R O:::::O     O:::::O             S:::::S   E:::::E                      T:::::T                 T:::::T        A:::::::::::::::::::::A     \n"
         "  R::::R     R:::::R O::::::O   O::::::O             S:::::S   E:::::E       EEEEEE         T:::::T                 T:::::T       A:::::AAAAAAAAAAAAA:::::A    \n"
         "RR:::::R     R:::::R O:::::::OOO:::::::O SSSSSSS     S:::::S EE::::::EEEEEEEE:::::E       TT:::::::TT             TT:::::::TT    A:::::A             A:::::A   \n"
         "R::::::R     R:::::R  OO:::::::::::::OO  S::::::SSSSSS:::::S E::::::::::::::::::::E       T:::::::::T             T:::::::::T   A:::::A               A:::::A  \n"
         "R::::::R     R:::::R    OO:::::::::OO    S:::::::::::::::SS  E::::::::::::::::::::E       T:::::::::T             T:::::::::T  A:::::A                 A:::::A \n"
         "RRRRRRRR     RRRRRRR      OOOOOOOOO       SSSSSSSSSSSSSSS    EEEEEEEEEEEEEEEEEEEEEE       TTTTTTTTTTT             TTTTTTTTTTT AAAAAAA                   AAAAAAA\n"
        ,wxPoint(150, 10)
        ,wxSize(1600, 350)
        ,wxTE_READONLY | wxTE_MULTILINE | wxNO_BORDER
    );

    /* Create a Monospace Bold font */
    wxFont Monospace_Bold
	  (12, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);

    /* Apply the font */
    ROSETTA_LABEL->SetFont(Monospace_Bold);
    btn_reg->SetFont(Monospace_Bold);
    btn_login->SetFont(Monospace_Bold);

    ROSETTA_LABEL->SetForegroundColour(*wxRED);
    ROSETTA_LABEL->SetBackgroundColour(*wxBLACK);

    this->SetBackgroundColour(*wxBLACK);
}

/* Destructor - no parameters, no code in function body */
cMain::~cMain(){}

void cMain::BtnClickLogin(wxCommandEvent &evt){

    btn_reg->Hide();
    btn_login->Hide();
    btn_quit->Hide();

    btn_login_GO->Show();
    btn_login_BACK->Show();

    password_input->Show();

    /* Finish the event. */
    evt.Skip();

    return;
}

void cMain::BtnClickLoginGo(wxCommandEvent &evt){

    uint8_t login_status = 0;
    uint8_t password[16];
    int password_len;

    wxString pwd_as_wxstring = "";

    info_msg_box->Hide();

    //password_input->AppendText("\0");
    pwd_as_wxstring = password_input->GetValue();
    password_len    = pwd_as_wxstring.Length();

    if(password_len > 15 || password_len < 5){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Enter 5 to 15 characters.");
        info_msg_box->Show();
        /* Finish the event. */
        evt.Skip();
        return;
    }

    strncpy( (char*)password
            ,(const char*)pwd_as_wxstring.mb_str(wxConvUTF8)
            ,password_len
    );

    /* 4 function pointers for my internet sockets interface are set here. */

    init_communication = tcp_init_communication;
    transmit_payload   = tcp_transmit_payload;
    receive_payload    = tcp_receive_payload;
    end_communication  = tcp_end_communication;

    login_status = login(password, password_len, "./user-save.dat");

    if(login_status == 1){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Login failed unexpectedly.");
        info_msg_box->Show();
    }
    else if(login_status == 10){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Rosetta is full right now. Try again later.");
        info_msg_box->Show();
    }
    else{
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Success! You are now logged in Rosetta!");
        info_msg_box->Show();

        btn_makeroom->Show();
        btn_joinroom->Show();
        btn_quit->Show();

        btn_login_GO->Hide();
        btn_login_BACK->Hide();

        password_input->Hide();
    }

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickLoginBack(wxCommandEvent &evt){

    btn_reg->Show();
    btn_login->Show();
    btn_quit->Show();

    btn_login_GO->Hide();
    btn_login_BACK->Hide();

    password_input->SetValue("");
    password_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickRegister(wxCommandEvent &evt){

    btn_reg->Hide();
    btn_login->Hide();
    btn_quit->Hide();

    btn_reg_GO->Show();
    btn_reg_BACK->Show();

    password_input->Show();

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickRegGo(wxCommandEvent &evt){

    uint8_t register_status = 1;
    uint8_t password[16];
    int password_len;
    wxString pwd_as_wxstring = "";

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    pwd_as_wxstring = password_input->GetValue();
    password_len    = pwd_as_wxstring.Length();

    if(password_len > 15 || password_len < 5){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error: Password must be 5 to 15 characters.");
        info_msg_box->Show();
        goto label_exit;
    }

    //password_input->AppendText("\0");

    strncpy( (char*)password
            ,(const char*)pwd_as_wxstring.mb_str(wxConvUTF8)
            ,password_len
    );

    /* At this point we're sure the password is valid. Register the user. */
    register_status = reg(password, password_len, "./user-save.dat");

    /* Display error box that something went wrong, try again. */
    if(register_status){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error: Something went wrong. Try again.");
        info_msg_box->Show();
        goto label_exit;
    }

    /* Change GUI to reflect successful registration, say GOOD in msg box
     * and go back to login screen, keep the "reg went ok, now login" box up.
     */
    else{
        info_msg_box->SetValue("");

        info_msg_box->WriteText
        ("Successful registration!\nSave File created.\nYou may login now.");

        info_msg_box->Show();

        btn_reg->Show();
        btn_login->Show();

        btn_reg_GO->Hide();
        btn_reg_BACK->Hide();

        password_input->SetValue("");
        password_input->Hide();
    }

label_exit:

    /* Finish the event. */
    evt.Skip();
    return;
}

void cMain::BtnClickRegBack(wxCommandEvent &evt){

    btn_reg->Show();
    btn_login->Show();
    btn_quit->Show();

    btn_reg_GO->Hide();
    btn_reg_BACK->Hide();

    password_input->SetValue("");
    password_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickMakeRoom(wxCommandEvent &evt){

    btn_makeroom->Hide();
    btn_joinroom->Hide();
    btn_quit->Hide();

    btn_makeroom_GO->Show();
    btn_makeroom_BACK->Show();

    roomid_input->Show();
    userid_input->Show();

    /* Finish the event. */
    evt.Skip();

    return;

}


void cMain::BtnClickJoinRoom(wxCommandEvent &evt){

    btn_makeroom->Hide();
    btn_joinroom->Hide();
    btn_quit->Hide();

    btn_joinroom_GO->Show();
    btn_joinroom_BACK->Show();

    roomid_input->Show();
    userid_input->Show();

    /* Finish the event. */
    evt.Skip();

    return;

}

void cMain::BtnClickJoinRoomGo(wxCommandEvent &evt){

    uint8_t joinroom_status = 1;
    uint8_t roomid[SMALL_FIELD_LEN];
    int roomid_len;

    wxString roomid_as_wxstring = "";
    wxString userid_as_wxstring = "";

    info_msg_box->Hide();

    roomid_as_wxstring = roomid_input->GetValue();
    userid_as_wxstring = userid_input->GetValue();

    roomid_len = roomid_as_wxstring.Length();
    userid_len = userid_as_wxstring.Length();

    printf("[DEBUG] WX: Joining room : Obtained roomid_len=%d, userid_len=%d\n"
           ,roomid_len, userid_len
          );

    if(roomid_len > 7 || roomid_len < 2 || userid_len > 7 || userid_len < 2){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Bad: Enter 2 to 7 characters for each field.");
        info_msg_box->Show();

        /* Finish the event. */
        evt.Skip();
        return;
    }

    strncpy( (char*)roomid
            ,(const char*)roomid_as_wxstring.mb_str(wxConvUTF8)
            ,roomid_len
    );

    memset(userid, 0x00, SMALL_FIELD_LEN);

    strncpy( (char*)userid
            ,(const char*)userid_as_wxstring.mb_str(wxConvUTF8)
            ,userid_len
    );

    joinroom_status = join_chatroom(roomid, roomid_len,
									(unsigned char*)userid, userid_len);

    if(joinroom_status){
        /* Add code to render 'could not join room' msg on user's screen. */
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Room joining failed unexpectedly.");
        info_msg_box->Show();
    }
    else{
        //info_msg_box->SetValue("");
        //info_msg_box->WriteText("Success! You've now joined the chatroom!");
        //info_msg_box->Show();

		btn_joinroom_GO->Hide();
        btn_joinroom_BACK->Hide();
        roomid_input->Hide();
        userid_input->Hide();

		btn_leavetheroom->Show();
		btn_send_msg->Show();
		msg_entries->Show();
		usermsg_input->Show();
    }

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickJoinRoomBack(wxCommandEvent &evt){

    btn_makeroom->Show();
    btn_joinroom->Show();
    btn_quit->Show();

    btn_joinroom_GO->Hide();
    btn_joinroom_BACK->Hide();

    roomid_input->SetValue("");
    roomid_input->Hide();

    userid_input->SetValue("");
    userid_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* Finish the event. */
    evt.Skip();

}

void cMain::BtnClickMakeRoomGo(wxCommandEvent &evt){

    uint8_t makeroom_status = 1;
    uint8_t roomid[SMALL_FIELD_LEN];
    int roomid_len;

    wxString roomid_as_wxstring = "";
    wxString userid_as_wxstring = "";

    info_msg_box->Hide();

    roomid_as_wxstring = roomid_input->GetValue();
    userid_as_wxstring = userid_input->GetValue();


    roomid_len = roomid_as_wxstring.Length();
    userid_len = userid_as_wxstring.Length();

    printf("[DEBUG] WX: Obtained roomid_len=%d, userid_len=%d\n",
	       roomid_len, userid_len);

    if(roomid_len > 7 || roomid_len < 2 || userid_len > 7 || userid_len < 2){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Bad: Enter 2 to 7 characters for each field.");
        info_msg_box->Show();

        /* Finish the event. */
        evt.Skip();
        return;
    }

    //roomid_input->AppendText("\0");
    //userid_input->AppendText("\0");

    strncpy( (char*)roomid
            ,(const char*)roomid_as_wxstring.mb_str(wxConvUTF8)
            ,roomid_len
    );

    memset(userid, 0x00, SMALL_FIELD_LEN);

    strncpy( (char*)userid
            ,(const char*)userid_as_wxstring.mb_str(wxConvUTF8)
            ,userid_len
    );

    makeroom_status = make_new_chatroom(roomid, roomid_len,
										(unsigned char*)userid, userid_len);

    if(makeroom_status == 1){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Room creation failed unexpectedly.");
        info_msg_box->Show();
    }
    else if(makeroom_status == 10){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Rosetta is full right now. Try again later.");
        info_msg_box->Show();
    }
    else{
        /* And to hide the rendering of the login stuff. */
        //info_msg_box->SetValue("");
        //info_msg_box->WriteText("Success! Your chat room has been created!");
        //info_msg_box->Show();

		btn_joinroom_GO->Hide();
        btn_joinroom_BACK->Hide();
        roomid_input->Hide();
        userid_input->Hide();

        btn_closeyourroom->Show();
        btn_send_msg->Show();
        msg_entries->Show();
        usermsg_input->Show();
    }

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickMakeRoomBack(wxCommandEvent &evt){

    btn_makeroom->Show();
    btn_joinroom->Show();
    btn_quit->Show();

    btn_makeroom_GO->Hide();
    btn_makeroom_BACK->Hide();

    roomid_input->SetValue("");
    roomid_input->Hide();

    userid_input->SetValue("");
    userid_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* Finish the event. */
    evt.Skip();
}

void cMain::BtnClickQuit(__attribute__((unused)) wxCommandEvent &evt){
    exit(0);
}

void cMain::BtnClickSendMsg(wxCommandEvent &evt)
{
	uint8_t  send_msg_status;
	uint8_t  msg_buf[MAX_TXT_LEN];
    int      msg_len;
	wxString msg_as_wxstring = "";

	memset(msg_buf, 0x00, MAX_TXT_LEN);
	msg_as_wxstring = usermsg_input->GetValue();
	msg_len = msg_as_wxstring.Length();
	usermsg_input->SetValue("");

	//std::cout << "Obtained entered txt message: " << msg_as_wxstring << "\n";
	//std::cout << "Length: " << msg_len << "\n";

	if(msg_len >= MAX_TXT_LEN || msg_len < 1){
		std::cout << "Entered ret on error. msg_len: " << msg_len << std::endl;
        evt.Skip();
        return;
    }
    strncpy( (char*)msg_buf,
			 (const char*)(msg_as_wxstring.mb_str(wxConvUTF8)),
			 msg_len
	);

    send_msg_status = send_text(msg_buf, msg_len);

	if(send_msg_status){
        printf("[ERR] Sending a message failed: %u. Closing Rosetta.\n",
			   send_msg_status);
		exit(1);
	}

    /* Put that user's message into their own UI too. */
	//msg_entries->SetEditable(true);
	for(uint8_t i = 0; i < (SMALL_FIELD_LEN - 1 - userid_len); ++i){
        msg_entries->AppendText(" ");
	}
	msg_entries->AppendText(wxString::FromUTF8((const char*)userid,userid_len));
	msg_entries->AppendText(": ");
    msg_entries->AppendText(msg_as_wxstring);
    msg_entries->AppendText("\n");

	//msg_entries->Refresh();
    //msg_entries->Update();
	//msg_entries->SetEditable(false);

    evt.Skip();
	return;
}

void cMain::BtnClickCloseYourRoom(wxCommandEvent &evt){

	evt.Skip();
}

void cMain::BtnClickLeaveTheRoom(wxCommandEvent &evt){

	evt.Skip();
}
