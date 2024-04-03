#include <gtk/gtk.h>
#include <string.h>

static void my_func (GtkWidget *widget, gpointer data){
	g_print ("Hello World\n");
	return;
}

static void activate (GtkApplication *app, gpointer user_data){

	const gchar  *label_btn_reg = "Register"
				,*label_btn_log = "Login"
	            ,*label_ROSETTA_CSSname = "CSS_label_ROSETTA"
	            ; 

	GtkWidget *window
			 ,*grid_main
			 ,*label_empty
			 ,*label_empty2
			 ,*label_empty3
			 ,*label_ROSETTA
			 ,*btn_log
			 ,*btn_reg
			 ;


	window = gtk_application_window_new (app);
	gtk_window_set_title (GTK_WINDOW (window), "Rosetta");
	gtk_window_set_default_size (GTK_WINDOW (window), 1920, 1080);


	grid_main = gtk_grid_new();
	


	gtk_window_set_child (GTK_WINDOW (window), grid_main);



	label_empty  = gtk_label_new("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	label_empty2 = gtk_label_new("\n");
	label_empty3 = gtk_label_new("\n");
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
	gtk_grid_attach(GTK_GRID(grid_main), label_empty3,   0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid_main), label_ROSETTA, 0, 1, 16, 1);
	gtk_grid_attach(GTK_GRID(grid_main), label_empty,   0, 2, 1, 1);
	

	
	/*--------------------------------------------------------*/
	
	/* Define Register and Login buttons. */
	btn_log = gtk_button_new_with_label(label_btn_log);
	btn_reg = gtk_button_new_with_label(label_btn_reg);

	/*
	g_signal_connect (button, "clicked", G_CALLBACK (my_func), NULL);
	*/

	/* Put the 2 buttons inside the main grid */

	
	gtk_grid_attach (
					  GTK_GRID(grid_main),
					  btn_log,
					  9, /* column */
					  4,  /* row    */
					  1,  /* width  */
					  1   /* height */
					);
	
	gtk_grid_attach(GTK_GRID(grid_main), label_empty2,   9, 5, 1, 1);
	
	gtk_grid_attach (
					  GTK_GRID(grid_main),
					  btn_reg,
					  9, /* column */
					  6,  /* row    */
					  1,  /* width  */
					  1   /* height */
					);
	
    //gtk_grid_set_column_homogeneous( GTK_GRID(grid_main), TRUE);
    //gtk_grid_set_row_homogeneous(    GTK_GRID(grid_main), TRUE);

	/* Add GTK-CSS styling to make the borders actually visible and red. */
	
	/* Give it a CSS-recognizable name. */
	gtk_widget_set_name(label_ROSETTA, label_ROSETTA_CSSname);
	
	/* Load the CSS file into this GTK app */
	GtkCssProvider *cssProvider = gtk_css_provider_new();
	
	gtk_css_provider_load_from_data(
		cssProvider,
		"frame{border:14px solid red;}\n"
	    "label#CSS_label_ROSETTA{font-size:14px;color:rgb(245, 207, 54);}\n"
	    "label{font-family:monospace;}\n"
	    "button{font-family:monospace;color:rgb(245, 207, 54);font-size:16px;}\n"
	    "window{background-color:rgb(25,25,25);}\n"
	    "box{font-family:monospace;}\0"
		,strlen(
		"frame{border:14px solid red;}\n"
	    "label#CSS_label_ROSETTA{font-size:14px;color:rgb(245, 207, 54);}\n"
	    "label{font-family:monospace;}\n"
	    "button{font-family:monospace;color:rgb(245, 207, 54);font-size:16px;}\n"
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

