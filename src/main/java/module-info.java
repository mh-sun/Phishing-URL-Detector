module com.example.phishing_detector {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.phishing_detector to javafx.fxml;
    exports com.example.phishing_detector;
}