#include "cMain.h"

/* Implement what the Event Table is.
 *
 * Parm 1 - the class it is producing the events for.
 * Parm 2 - it also requires the base class that parm 1 inherited from.
 */
BEGIN_EVENT_TABLE(cMain, wxFrame)
    EVT_BUTTON(10001, cMain::OnButtonClicked)
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
    
    /* do the second padlock image now.*/
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
    
}
    
    
/* Destructor - no parameters, no code in function body */
cMain::~cMain()
{
    /* empty destructor function body */
}

void cMain::OnButtonClicked(wxCommandEvent &evt){

    /* Do something when the button has been clicked. */
    
    
    
    /* Tell the system that this event has been handled by telling the event
     * that it has finished, by calling its Skip() member function.
     */
    evt.Skip();
    
}



