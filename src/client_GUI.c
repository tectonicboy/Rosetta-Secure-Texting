#include <gtk/gtk.h>
#include <string.h>
#include "coreutil.h"
#include "client_util.h"


static void func_login    (GtkWidget *widget, gpointer data);
static void func_register (GtkWidget *widget, gpointer data);                 
static void func_back_log (GtkWidget *widget, gpointer data);    
static void func_back_reg (GtkWidget *widget, gpointer data);
static void func_go_log      (GtkWidget *widget, gpointer data);
static void func_go_reg      (GtkWidget *widget, gpointer data);

GtkWidget *window
         ,*grid_main
         ,*label_emptyM0
         ,*label_emptyM1
         ,*label_emptyM2
         ,*label_emptyM3
         ,*label_emptyM4
         ,*label_emptyMA
         ,*label_emptyMB
         ,*label_emptyM5
         ,*label_empty2
         ,*label_empty3
         ,*label_empty4
         ,*label_empty5
         ,*label_ROSETTA
         ,*btn_log
         ,*btn_reg
         ,*entry_log
         ,*entry_reg
         ,*label_log
         ,*label_reg
         ,*btn_go_log
         ,*btn_go_reg
         ,*btn_back_log
         ,*btn_back_reg
         ,*label_warn_regoverwrite = NULL
         ,*label_warn_noregfound = NULL
         ;
         
         
const gchar  *label_btn_reg = "Register"
            ,*label_btn_log = "Login"
            ,*label_ROSETTA_CSSname = "CSS_label_ROSETTA"
            ,*label_btn_go_log = "Proceed"
            ,*label_btn_go_reg = "Proceed"
            ,*label_btn_back_log = "Back"
            ,*label_btn_back_reg = "Back"
            ; 
        
static void func_go_reg(GtkWidget *widget, gpointer data){

    GtkEntryBuffer* passbuf;
    const char* pass_txt;
    guint16 entered_passlen = gtk_entry_get_text_length(GTK_ENTRY(entry_reg));
    uint8_t reg_status;
    
    if ( ! (entered_passlen < 6 || entered_passlen > 16)) {
        passbuf  = gtk_entry_get_buffer(GTK_ENTRY(entry_reg));
        pass_txt = gtk_entry_buffer_get_text(GTK_ENTRY_BUFFER(passbuf));
        reg_status = create_save(pass_txt, (uint16_t)entered_passlen);
        
        gtk_grid_remove(GTK_GRID(grid_main), label_reg);
        
        if(reg_status != 0){
            label_reg = gtk_label_new("Registration error.\nTry again.");
        }
        else{
            label_reg = gtk_label_new("Success!\nGo back to login.");
        }
        
        gtk_grid_attach(GTK_GRID(grid_main), label_reg, 9, 3, 1, 1);
    }

    return;
} 

static void func_go_log(GtkWidget *widget, gpointer data){

    GtkEntryBuffer* passbuf;
    const char* pass_txt;
    guint16 entered_passlen = gtk_entry_get_text_length(GTK_ENTRY(entry_log));
    uint8_t login_status;
    
    if ( ! (entered_passlen < 6 || entered_passlen > 16)) {
        passbuf  = gtk_entry_get_buffer(GTK_ENTRY(entry_log));
        pass_txt = gtk_entry_buffer_get_text(GTK_ENTRY_BUFFER(passbuf));
        
        login_status = login(pass_txt, (uint16_t)entered_passlen);

        gtk_grid_remove(GTK_GRID(grid_main), label_log);
                
        if(login_status != 0){
            label_log = gtk_label_new("Login error. Try again.\n"
                                      "Or register anew."
                                     );    
        }
        else{
            label_log = gtk_label_new("Login successful!");
        }
        
        gtk_grid_attach(GTK_GRID(grid_main), label_log, 9, 3, 1, 1);
    }
}

static void func_register(GtkWidget *widget, gpointer data){

    if(label_warn_noregfound != NULL){
        gtk_grid_remove(GTK_GRID(grid_main), label_warn_noregfound);
        label_warn_noregfound = NULL;    
    }
    
    
    FILE* saved;
    
    if ( (saved = fopen("saved.dat","r")) != NULL){
        label_warn_regoverwrite = gtk_label_new("Erases your existing save.");
        gtk_grid_attach(GTK_GRID(grid_main), label_warn_regoverwrite, 9, 8, 1, 1);
        fclose(saved);
    }


    gtk_grid_remove(GTK_GRID(grid_main), btn_log);
    gtk_grid_remove(GTK_GRID(grid_main), btn_reg);

    btn_go_reg   = gtk_button_new_with_label(label_btn_go_reg);
    btn_back_reg = gtk_button_new_with_label(label_btn_back_reg);

    g_signal_connect(btn_go_reg,   "clicked", G_CALLBACK(func_go_reg),   NULL);
    g_signal_connect(btn_back_reg, "clicked", G_CALLBACK(func_back_reg), NULL);
    
    label_reg = gtk_label_new(
                "Pick a new password\n6 to 16 symbols.\nTakes a few seconds.");
    
    entry_reg = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry_reg), FALSE);

    gtk_grid_attach(GTK_GRID(grid_main), label_reg, 9, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), entry_reg, 9,4,1,1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_go_reg, 9,5,1,1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_back_reg, 9,6,1,1);
    
    return;
}

static void func_login(GtkWidget *widget, gpointer data){

    FILE* saved;
    
    if ( (saved = fopen("saved.dat","r")) == NULL){
        if(label_warn_noregfound != NULL){
            gtk_grid_remove(GTK_GRID(grid_main), label_warn_noregfound);
            label_warn_noregfound = NULL;    
        }
        label_warn_noregfound = gtk_label_new("Register first");
        gtk_grid_attach(GTK_GRID(grid_main), label_warn_noregfound, 9, 8, 1, 1);
        return;
    }

    if(saved) { fclose(saved); }    
    
    gtk_grid_remove(GTK_GRID(grid_main), btn_log);
    gtk_grid_remove(GTK_GRID(grid_main), btn_reg);
    
    btn_go_log   = gtk_button_new_with_label(label_btn_go_log);
    btn_back_log = gtk_button_new_with_label(label_btn_back_log);
    
    g_signal_connect(btn_back_log, "clicked", G_CALLBACK(func_back_log), NULL);
    g_signal_connect(btn_go_log,   "clicked", G_CALLBACK(func_go_log),   NULL);    
    
    label_log = gtk_label_new("Enter your password.\nTakes a few seconds.");
    
    entry_log = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry_log), FALSE);
    
    gtk_grid_attach(GTK_GRID(grid_main), label_log, 9, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), entry_log, 9,4,1,1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_go_log, 9,5,1,1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_back_log, 9,6,1,1);
    
    return;
}


static void func_back_reg(GtkWidget *widget, gpointer data){

    if(label_warn_regoverwrite != NULL){
        gtk_grid_remove(GTK_GRID(grid_main), label_warn_regoverwrite);
        label_warn_regoverwrite = NULL;
    }
    gtk_grid_remove(GTK_GRID(grid_main), label_reg);
    gtk_grid_remove(GTK_GRID(grid_main), entry_reg);
    gtk_grid_remove(GTK_GRID(grid_main), btn_go_reg);
    gtk_grid_remove(GTK_GRID(grid_main), btn_back_reg);

    btn_log = gtk_button_new_with_label(label_btn_log);
    btn_reg = gtk_button_new_with_label(label_btn_reg);
    g_signal_connect(btn_log, "clicked", G_CALLBACK(func_login),    NULL);
    g_signal_connect(btn_reg, "clicked", G_CALLBACK(func_register), NULL);
    gtk_grid_attach(GTK_GRID(grid_main), btn_log, 9, 10,  1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_reg, 9, 12, 1, 1);

    return;
}

static void func_back_log(GtkWidget *widget, gpointer data){

    gtk_grid_remove(GTK_GRID(grid_main), label_log);
    gtk_grid_remove(GTK_GRID(grid_main), entry_log);
    gtk_grid_remove(GTK_GRID(grid_main), btn_go_log);
    gtk_grid_remove(GTK_GRID(grid_main), btn_back_log);
    
    btn_log = gtk_button_new_with_label(label_btn_log);
    btn_reg = gtk_button_new_with_label(label_btn_reg);
    g_signal_connect(btn_log, "clicked", G_CALLBACK(func_login),    NULL);
    g_signal_connect(btn_reg, "clicked", G_CALLBACK(func_register), NULL);
    gtk_grid_attach(GTK_GRID(grid_main), btn_log, 9, 10,  1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), btn_reg, 9, 12, 1, 1);

    return;
}

static void activate (GtkApplication *app, gpointer user_data){

    window = gtk_application_window_new (app);
    gtk_window_set_title (GTK_WINDOW (window), "Rosetta Secure Texting");
    gtk_window_set_default_size (GTK_WINDOW (window), 1920, 1080);

    grid_main = gtk_grid_new();
    
    gtk_window_set_child (GTK_WINDOW (window), grid_main);

    label_emptyM0 = gtk_label_new("\n\n\n\n\n\n\n");
    label_emptyM1 = gtk_label_new("\n");
    label_emptyM2 = gtk_label_new("\n");
    label_emptyM3 = gtk_label_new("\n");
    label_emptyM4 = gtk_label_new("\n");
    label_emptyMA = gtk_label_new("\n");
    label_emptyMB = gtk_label_new("\n");
    label_emptyM5 = gtk_label_new("\n\n\n\n\n");
    label_empty2  = gtk_label_new("\n");
    label_empty3  = gtk_label_new("\n");
    label_empty4  = gtk_label_new("\n");
    label_empty5  = gtk_label_new("\n");

    label_ROSETTA = gtk_label_new( 
        "                                            "                                                                                                                                                                                                           
        "RRRRRRRRRRRRRRRRR         OOOOOOOOO         SSSSSSSSSSSSSSS  EEEEEEEEEEEEEEEEEEEEEE TTTTTTTTTTTTTTTTTTTTTTT TTTTTTTTTTTTTTTTTTTTTTT          AAA\n"             
        "                                            "
        "R::::::::::::::::R      OO:::::::::OO     SS:::::::::::::::S E::::::::::::::::::::E T:::::::::::::::::::::T T:::::::::::::::::::::T         A:::A\n"              
        "                                            "
        "R::::::RRRRRR:::::R   OO:::::::::::::OO  S:::::SSSSSS::::::S E::::::::::::::::::::E T:::::::::::::::::::::T T:::::::::::::::::::::T        A:::::A\n"             
        "                                            "
        "RR:::::R     R:::::R O:::::::OOO:::::::O S:::::S     SSSSSSS EE::::::EEEEEEEEE::::E T:::::TT:::::::TT:::::T T:::::TT:::::::TT:::::T       A:::::::A\n"            
        "                                            "
        "  R::::R     R:::::R O::::::O   O::::::O S:::::S               E:::::E       EEEEEE TTTTTT  T:::::T  TTTTTT TTTTTT  T:::::T  TTTTTT      A:::::::::A\n"           
        "                                            "
        "  R::::R     R:::::R O:::::O     O:::::O S:::::S               E:::::E                      T:::::T                 T:::::T             A:::::A:::::A\n"          
        "                                            "
        "  R::::RRRRRR:::::R  O:::::O     O:::::O  S::::SSSS            E::::::EEEEEEEEEE            T:::::T                 T:::::T            A:::::A A:::::A\n"         
        "                                            "
        "  R:::::::::::::RR   O:::::O     O:::::O   SS::::::SSSSS       E:::::::::::::::E            T:::::T                 T:::::T           A:::::A   A:::::A\n"        
        "                                            "
        "  R::::RRRRRR:::::R  O:::::O     O:::::O     SSS::::::::SS     E:::::::::::::::E            T:::::T                 T:::::T          A:::::A     A:::::A\n"       
        "                                            "
        "  R::::R     R:::::R O:::::O     O:::::O        SSSSSS::::S    E::::::EEEEEEEEEE            T:::::T                 T:::::T         A:::::AAAAAAAAA:::::A\n"      
        "                                            "
        "  R::::R     R:::::R O:::::O     O:::::O             S:::::S   E:::::E                      T:::::T                 T:::::T        A:::::::::::::::::::::A\n"     
        "                                            "
        "  R::::R     R:::::R O::::::O   O::::::O             S:::::S   E:::::E       EEEEEE         T:::::T                 T:::::T       A:::::AAAAAAAAAAAAA:::::A\n"    
        "                                            "
        "RR:::::R     R:::::R O:::::::OOO:::::::O SSSSSSS     S:::::S EE::::::EEEEEEEE:::::E       TT:::::::TT             TT:::::::TT    A:::::A             A:::::A\n"   
        "                                            "
        "R::::::R     R:::::R  OO:::::::::::::OO  S::::::SSSSSS:::::S E::::::::::::::::::::E       T:::::::::T             T:::::::::T   A:::::A               A:::::A\n"  
        "                                            "
        "R::::::R     R:::::R    OO:::::::::OO    S:::::::::::::::SS  E::::::::::::::::::::E       T:::::::::T             T:::::::::T  A:::::A                 A:::::A\n" 
        "                                            "
        "RRRRRRRR     RRRRRRR      OOOOOOOOO       SSSSSSSSSSSSSSS    EEEEEEEEEEEEEEEEEEEEEE       TTTTTTTTTTT             TTTTTTTTTTT AAAAAAA                   AAAAAAA\n"
    ); 
    
    gtk_grid_attach(GTK_GRID(grid_main), label_empty3,  0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_ROSETTA, 0, 1, 16, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM0, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM1, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM2, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM3, 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM4, 0, 6, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyMA, 0, 7, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyMB, 0, 8, 1, 1);
    gtk_grid_attach(GTK_GRID(grid_main), label_emptyM5, 0, 9, 1, 1);
    /*--------------------------------------------------------*/

    /*--------------------------------------------------------*/
    
    /* Define Register and Login buttons. */
    btn_log      = gtk_button_new_with_label(label_btn_log);
    btn_reg      = gtk_button_new_with_label(label_btn_reg);

    g_signal_connect(btn_log, "clicked", G_CALLBACK(func_login),    NULL);
    g_signal_connect(btn_reg, "clicked", G_CALLBACK(func_register), NULL);
    

    gtk_grid_attach (
                      GTK_GRID(grid_main),
                      btn_log,
                      9,  /* column */
                      10,  /* row    */
                      1,  /* width  */
                      1   /* height */
                    );
    
    gtk_grid_attach(GTK_GRID(grid_main), label_empty2,   9, 11, 1, 1);
    
    gtk_grid_attach (
                      GTK_GRID(grid_main),
                      btn_reg,
                      9,   /* column */
                      12,  /* row    */
                      1,   /* width  */
                      1    /* height */
                    );
    
    
    /* Add GTK-CSS styling to make the borders actually visible and red. */
    
    /* Give it a CSS-recognizable name. */
    gtk_widget_set_name(label_ROSETTA, label_ROSETTA_CSSname);
    
    /* Load the CSS file into this GTK app */
    GtkCssProvider *cssProvider = gtk_css_provider_new();
    
    gtk_css_provider_load_from_data(
        cssProvider,
        "frame{border:14px solid red;}\n"
        "label#CSS_label_ROSETTA{font-size:14px;color:rgb(230, 2, 2);}\n"
        "label{font-family:monospace;}\n"
        "button{font-family:monospace;color:rgb(230, 2, 2);font-size:16px;}\n"
        "window{background-color:rgb(25,25,25);}\n"
        "box{font-family:monospace;}\0"
        ,strlen(
        "frame{border:14px solid red;}\n"
        "label#CSS_label_ROSETTA{font-size:14px;color:rgb(230, 2, 2);}\n"
        "label{font-family:monospace;}\n"
        "button{font-family:monospace;color:rgb(230, 2, 2);font-size:16px;}\n"
        "window{background-color:rgb(25,25,25);}\n"
        "box{font-family:monospace;}\0"
        )
    );
    
    gtk_style_context_add_provider_for_display(  gdk_display_get_default()
                                                  ,GTK_STYLE_PROVIDER(cssProvider)
                                                  ,GTK_STYLE_PROVIDER_PRIORITY_USER
                                                );
                                                 
    /* Render the GUI */
    gtk_window_present (GTK_WINDOW (window));
    return;
}

int main(int argc, char** argv)
{
    GtkApplication *app;
    int status;

    app = gtk_application_new ("Rosetta.Systems", G_APPLICATION_FLAGS_NONE);

    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);

    status = g_application_run (G_APPLICATION (app), argc, argv);

    g_object_unref (app);

    return status;
}

