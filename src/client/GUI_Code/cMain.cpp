#include "cMain.h"
#include "../Network_Code/TCP_client.h"

/* Implement what the Event Table is.
 *
 * Parm 1 - the class it is producing the events for.
 * Parm 2 - it also requires the base class that parm 1 inherited from.
 */
BEGIN_EVENT_TABLE(cMain, wxFrame)
    EVT_BUTTON(10001, cMain::BtnClickLogin    )
    EVT_BUTTON(10002, cMain::BtnClickRegister )
    EVT_BUTTON(10003, cMain::BtnClickLoginGo  )
    EVT_BUTTON(10004, cMain::BtnClickLoginBack)
    EVT_BUTTON(10005, cMain::BtnClickRegGo    )
    EVT_BUTTON(10006, cMain::BtnClickRegBack  )
END_EVENT_TABLE()

/* Constructor - uses constructor of wxFrame with parameters. */
cMain::cMain() : wxFrame( 
                   nullptr           
                  ,wxID_ANY            /* Give it any ID, doesn't matter */
                  ,"Rosetta"           /* Title of the window            */
                  ,wxPoint(0, 0)       /* Where to spawn - top left      */
                  ,wxSize(1920, 1080) /* Size of the window in pixels   */
                 )
{
    /* Construct the button member variable. */
    btn_login = new wxButton( 
         this            /* Parent of the button - this window class      */
        ,10001           /* Match the ID we specified in the Event Table. */
        ,"Login"         /* Label of the button                           */ 
        ,wxPoint(850, 600) /* Spawn relative to top left corner of parent   */
        ,wxSize(200, 50) /* Width and height in pixels                    */
    );
    
    btn_reg = new wxButton( 
         this            /* Parent of the button - this window class      */
        ,10002           /* Match the ID we specified in the Event Table. */
        ,"Register"      /* Label of the button                           */ 
        ,wxPoint(850, 660) /* Spawn relative to top left corner of parent   */
        ,wxSize(200, 50) /* Width and height in pixels                    */
    );
    
    btn_login_GO = new wxButton(
        this
       ,10003
       ,"Go"
       ,wxPoint(850, 600)
       ,wxSize(200, 50)
    );

    btn_login_BACK = new wxButton(
        this
       ,10004
       ,"Back"
       ,wxPoint(850, 660)
       ,wxSize(200, 50)
    );

    btn_reg_GO = new wxButton(
        this
       ,10005
       ,"Go"
       ,wxPoint(850, 600)
       ,wxSize(200, 50)
    );

    btn_reg_BACK = new wxButton(
        this
       ,10006
       ,"Back"
       ,wxPoint(850, 660)
       ,wxSize(200, 50)
    ); 

    btn_quit = new wxButton(
        this
        ,wxID_ANY
        ,"Quit Rosetta"
        ,wxPoint(850, 720)
        ,wxSize(200, 50)
    );

    btn_login_GO->Hide();
    btn_login_BACK->Hide();
    btn_reg_GO->Hide();
    btn_reg_BACK->Hide();

    password_input = new wxTextCtrl( 
        this
        ,wxID_ANY
        ,""
        ,wxPoint(850, 750)
        ,wxSize(200, 50)
        ,wxTE_PASSWORD
    );

    password_input->SetHint("Your password...");

    info_msg_box = new wxTextCtrl(
        this
        ,wxID_ANY
        ,""
        ,wxPoint(725, 850)
        ,wxSize(500, 100)
        ,wxTE_READONLY | wxTE_MULTILINE
    );

    password_input->Hide();
    info_msg_box->Hide();



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
    
    // Create a Monospace Bold font
    wxFont Monospace_Bold( 12
                ,wxFONTFAMILY_MODERN
                ,wxFONTSTYLE_NORMAL
                ,wxFONTWEIGHT_BOLD
    );
   
    // Apply the font to the wxListBox
    ROSETTA_LABEL->SetFont(Monospace_Bold);
    btn_reg->SetFont(Monospace_Bold);
    btn_login->SetFont(Monospace_Bold);
    
    ROSETTA_LABEL->SetForegroundColour(*wxRED);
    ROSETTA_LABEL->SetBackgroundColour(*wxBLACK);
    
    this->SetBackgroundColour(*wxBLACK);

    // Load the JPG image from file

    /*
    wxImage::AddHandler(new wxPNGHandler());
    
    wxImage padlock_image;
    
    if ( padlock_image.LoadFile( "../resources/padlock_image.png"
                                ,wxBITMAP_TYPE_PNG
                               )
       )
    {
    
        //Convert wxImage to wxBitmap
        wxBitmap bitmap(padlock_image);

        //Create a wxStaticBitmap to display the image
        wxStaticBitmap* imageCtrl = new wxStaticBitmap(
            this
            ,wxID_ANY
            ,bitmap
            ,wxPoint(10, 330)
            ,wxSize(626, 626)
        );
    }
    
    else{
        wxMessageBox("Failed to load image!", "Error", wxICON_ERROR);
    }
    */

    /* do the second padlock image now.*/
    /*
    wxImage padlock_image2;
    
    if ( padlock_image2.LoadFile( "../resources/padlock_image.png"
                                ,wxBITMAP_TYPE_PNG
                               )
       )
    {
    
        //Convert wxImage to wxBitmap
        wxBitmap bitmap2(padlock_image2);

        //Create a wxStaticBitmap to display the image
        wxStaticBitmap* imageCtrl2 = new wxStaticBitmap(
            this
            ,wxID_ANY
            ,bitmap2
            ,wxPoint(1290, 330)
            ,wxSize(626, 626)
        );
    }
    
    else{
        wxMessageBox("Failed to load image!", "Error", wxICON_ERROR);
    }    
    */
}
    
    
/* Destructor - no parameters, no code in function body */
cMain::~cMain()
{
    /* empty destructor function body */
}

void cMain::BtnClickLogin(wxCommandEvent &evt){

    btn_reg->Hide();
    btn_login->Hide();

    btn_login_GO->Show();
    btn_login_BACK->Show();

    password_input->Show();

    /* End the event. */
    evt.Skip();
    
    return;
}

void cMain::BtnClickLoginGo(wxCommandEvent &evt){

    uint8_t login_status = 1;
    uint8_t password[16];
    int password_len;

    wxString pwd_as_wxstring;
    
    info_msg_box->Hide();

    pwd_as_wxstring = password_input->GetValue();
    password_len    = pwd_as_wxstring.Length();

    if(password_len > 15 || password_len < 5){
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Enter 5 to 15 characters.");
        info_msg_box->Show();
    }

    password_input->AppendText("\0");

    strncpy( (char*)password
            ,(const char*)pwd_as_wxstring.mb_str(wxConvUTF8)
            ,password_len
    );

    login_status = login(password, password_len);

    printf("Obtained user's entered password from GUI!\n");
    printf("password_len = %d\n", password_len);
    printf("password: %s\n", password);

    if(login_status == 0){
        /* Add code to render 'could not login rosetta' msg on user's screen. */
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Error. Login failed unexpectedly.");
        info_msg_box->Show();
    }
    else if(login_status == 3){
        /* Add code to render 'rosetta is full' msg on user's screen. */
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Rosetta is full right now. Try again later.");
        info_msg_box->Show();
    }
    else{
        /* Add code to render OK msg and buttons to join/create a chatroom. */
        /* And to hide the rendering of the login stuff. */      
        info_msg_box->SetValue("");
        info_msg_box->WriteText("Success! You are now logged in Rosetta!");
        info_msg_box->Show(); 
    }
    
    /* End the event. */
    evt.Skip();

}

void cMain::BtnClickLoginBack(wxCommandEvent &evt){

    btn_reg->Show();
    btn_login->Show();

    btn_login_GO->Hide();
    btn_login_BACK->Hide();

    password_input->SetValue("");
    password_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* End the event. */
    evt.Skip();
}

void cMain::BtnClickRegister(wxCommandEvent &evt){

    btn_reg->Hide();
    btn_login->Hide();

    btn_reg_GO->Show();
    btn_reg_BACK->Show();

    password_input->Show();

    /* End the event. */
    evt.Skip();
}

void cMain::BtnClickRegGo(wxCommandEvent &evt){

    uint8_t register_status = 1;
    uint8_t password[16];
    int password_len;
    wxString pwd_as_wxstring;
    
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

    password_input->AppendText("\0");

    strncpy( (char*)password
            ,(const char*)pwd_as_wxstring.mb_str(wxConvUTF8)
            ,password_len
    );

    /* At this point we're sure the password is valid. Register the user. */
    register_status = reg(password, password_len);

    /* Display error box that something went wrong, try again. */
    if(register_status == 0){
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

    /* End the event. */
    evt.Skip();
}

void cMain::BtnClickRegBack(wxCommandEvent &evt){

    btn_reg->Show();
    btn_login->Show();

    btn_reg_GO->Hide();
    btn_reg_BACK->Hide();

    password_input->SetValue("");
    password_input->Hide();

    info_msg_box->SetValue("");
    info_msg_box->Hide();

    /* End the event. */
    evt.Skip();
}
