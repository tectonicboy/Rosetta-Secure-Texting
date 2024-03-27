#include <gtk/gtk.h>

static void my_func (GtkWidget *widget, gpointer data){
	g_print ("Hello World\n");
	return;
}

static void activate (GtkApplication *app, gpointer user_data){

	const gchar  *label_btn_reg = "Register"
				,*label_btn_log = "Login"
	            ,*label_hlo_txt = "Welcome to Rosetta Secure Texting"
	            ,*label_hello_CSSname = "CSS_label_hello"
	            ; 
	           
	GtkWidget *window
			 ,*box_main
			 ,*box_left,    *frame_box_left
			 ,*box_mid,     *frame_box_mid
			 ,*box_right,   *frame_box_right
			 ,*box_welc,    *frame_box_welc
			 ,*box_logreg,  *frame_box_logreg
			 ,*label_hello
			 ,*btn_log
			 ,*btn_reg
			 ;

	window = gtk_application_window_new (app);
	gtk_window_set_title (GTK_WINDOW (window), "Rosetta");
	gtk_window_set_default_size (GTK_WINDOW (window), 1920, 1080);


	box_main = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_main), TRUE);
	
	gtk_window_set_child (GTK_WINDOW (window), box_main);


	box_left  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_left), TRUE);
	
	box_mid   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_mid), TRUE);
	
	box_right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_right), TRUE);
	
	gtk_box_append(GTK_BOX(box_main), box_left);
	gtk_box_append(GTK_BOX(box_main), box_mid);
	gtk_box_append(GTK_BOX(box_main), box_right);
	
	
	box_welc   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_main), TRUE);	
	
	box_logreg = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(box_main), TRUE);
	
	gtk_box_append(GTK_BOX(box_mid), box_welc);
	gtk_box_append(GTK_BOX(box_mid), box_logreg);
	
	
	
	
	frame_box_left = gtk_frame_new(NULL);
	gtk_frame_set_child(GTK_FRAME(frame_box_left), box_left);
	
	frame_box_mid = gtk_frame_new(NULL);
	gtk_frame_set_child(GTK_FRAME(frame_box_mid), box_mid);

	frame_box_right = gtk_frame_new(NULL);
	gtk_frame_set_child(GTK_FRAME(frame_box_right), box_right);
	
	frame_box_welc = gtk_frame_new(NULL);
	gtk_frame_set_child(GTK_FRAME(frame_box_welc), box_welc);
	
	frame_box_logreg = gtk_frame_new(NULL);
	gtk_frame_set_child(GTK_FRAME(frame_box_logreg), box_logreg);

	
	
	
	label_hello = gtk_label_new(label_hlo_txt);
	gtk_box_append(GTK_BOX(box_welc), label_hello);
	
	btn_log = gtk_button_new_with_label(label_btn_log);
	btn_reg = gtk_button_new_with_label(label_btn_reg);
	
	/*
	g_signal_connect (button, "clicked", G_CALLBACK (my_func), NULL);
	*/
	
	gtk_box_append(GTK_BOX(box_logreg), btn_reg);
	gtk_box_append(GTK_BOX(box_logreg), btn_log);
	
	/* Give it a CSS-recognizable name. */
	gtk_widget_set_name (label_hello, label_hello_CSSname);
	
	/* Load the CSS file into this GTK app */
	GtkCssProvider *cssProvider = gtk_css_provider_new();
	gtk_css_provider_load_from_string(cssProvider,
		".frame{border:10px solid red;} "
		"label#CSS_label_hello{font: 30px 'Comic Sans';}"
	);
	
	/*
    gtk_css_provider_load_from_file(cssProvider, "styles.css", NULL);
    
    gtk_style_context_add_provider_for_display(  gdk_screen_get_default()
                               				   ,GTK_STYLE_PROVIDER(cssProvider)
                               				   ,GTK_STYLE_PROVIDER_PRIORITY_USER
                               				 );
     */                          	
     
     			 
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

