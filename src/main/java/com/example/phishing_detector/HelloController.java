package com.example.phishing_detector;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Random;
import java.util.ResourceBundle;


public class HelloController implements Initializable {

    @FXML
    private TextField SFH;

    @FXML
    private TextField PopWin;

    @FXML
    private TextField SSL;

    @FXML
    private TextField ReqUrl;

    @FXML
    private TextField AncUrl;

    @FXML
    private TextField WebTraf;

    @FXML
    private TextField UrlLen;

    @FXML
    private TextField DomAge;

    @FXML
    private TextField IpAdd;

    @FXML
    private Label Result;

    @FXML
    private Label Succ;

    @FXML
    private Label Fail;

    @FXML
    private Label UserTest;

    File file;
    ArrayList<Integer> indices ;
    ArrayList<ArrayList<Integer>> data;
    String delimiter;
    int K;

    private void Initialize() {
        indices = new ArrayList<>();
        data = new ArrayList<>();

        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            while ((line = br.readLine())!=null){
                if(line.equals("")) continue;
                else if(line.charAt(0) == '@') continue;
                String[] arr = line.split(delimiter);
                ArrayList<Integer> temp = new ArrayList<>();
                for (String s : arr) {
                    temp.add(Integer.parseInt(s));
                }
                data.add(temp);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        for(int i=0;i<data.size();i++){
            indices.add(i);
        }
    }

    public void ShuffleIndex(ArrayList<Integer> array){
        Random rand = new Random();

        for (int i = 0; i < array.size(); i++) {
            int randomIndexToSwap = rand.nextInt(array.size());
            int temp = array.get(randomIndexToSwap);
            array.set(randomIndexToSwap,array.get(i));
            array.set(i,temp);
        }
    }

    public void CrossValidation(){
        int size = indices.size();
        int foldSize = size/10+1;

        int start=0;
        int limit = start+foldSize;

        int success=0,failure=0;

        for (int i=start;i<=limit;i++){
            double[] knnDistance = new double[K];
            for(int z=0;z<K;z++){
                knnDistance[z] = Double.POSITIVE_INFINITY;
            }
            int[] knnIndex = new int[K];

            for(int j=0;j<start;j++){
                GetKNN(data.get(indices.get(i)), knnDistance, knnIndex, j);
            }

            for(int j=limit+1;j<size;j++){
                GetKNN(data.get(indices.get(i)), knnDistance, knnIndex, j);
            }

            int lastIndex = data.get(0).size()-1;
            int predictedResult;
            predictedResult = DeterMineResult(knnIndex, lastIndex);

            if (data.get(indices.get(i)).get(lastIndex) == predictedResult)
                success++;
            else
                failure++;

            if(i==limit){
                start = limit+1;
                limit = start+foldSize;
                if (limit>=size)
                    limit=size-1;
            }
        }
        Result.setText(success*100/(success+failure)+"%");
        Succ.setText(success+"");
        Fail.setText(failure+"");
//        System.out.println("..............Accuracy: "+success*100/(success+failure)+"%.............");
//        System.out.println("Success: "+success+"\nFailure: "+failure);
    }

    private void GetKNN(ArrayList<Integer> arrayData, double[] knnDistance, int[] knnIndex, int j) {
        double temp = EuclideanDistance(arrayData,data.get(indices.get(j)));
        for(int z=0;z<K;z++){
            if(knnDistance[z]>temp)
            {
                knnDistance[z] = temp;
                knnIndex[z] = indices.get(j);
                break;
            }
        }
    }

    private double EuclideanDistance(ArrayList<Integer> point1,ArrayList<Integer> point2) {
        double dist=0;
        for (int i=0;i<point1.size()-1;i++){
            dist+=(Math.pow(point1.get(i)-point2.get(i),2));
        }
        return Math.pow(dist,0.5);

    }
    public void DataScaling(){
        for(ArrayList<Integer> arr:data){
            DataScaling(arr);
        }
    }
    public void DataScaling(ArrayList<Integer> arr){
        for(int i=0;i<arr.size()-1;i++){
            if(arr.get(i)==1){
                arr.set(i,4);
            }
            else if(arr.get(i)==0){
                arr.set(i,3);
            }
            else {
                arr.set(i,2);
            }
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        UserTest.setText("");
        this.file = new File("src/Data/PhishingData.arff");
        this.delimiter = ",";
        this.K = 7;
        Initialize();
        ShuffleIndex(this.indices);
        DataScaling();
    }

    public void TestData(){
        Initialize();
        ShuffleIndex(this.indices);
        DataScaling();
        CrossValidation();
    }
    public void TestFromUser(){
        ArrayList<Integer> userDefined = new ArrayList<>();
        userDefined.add(Integer.parseInt(SFH.getText()));
        userDefined.add(Integer.parseInt(PopWin.getText()));
        userDefined.add(Integer.parseInt(SSL.getText()));
        userDefined.add(Integer.parseInt(ReqUrl.getText()));
        userDefined.add(Integer.parseInt(AncUrl.getText()));
        userDefined.add(Integer.parseInt(WebTraf.getText()));
        userDefined.add(Integer.parseInt(UrlLen.getText()));
        userDefined.add(Integer.parseInt(DomAge.getText()));
        userDefined.add(Integer.parseInt(IpAdd.getText()));

        DataScaling(userDefined);

        double[] knnDistance = new double[K];
        for(int z=0;z<K;z++){
            knnDistance[z] = Double.POSITIVE_INFINITY;
        }
        int[] knnIndex = new int[K];

        for(int j=0;j<data.size();j++){
            GetKNN(userDefined, knnDistance, knnIndex, j);
        }

        int lastIndex = data.get(0).size()-1;
        int predictedResult;
        predictedResult=DeterMineResult(knnIndex, lastIndex);

        String site="";
        if(predictedResult == 1) site="SAFE";
        else if(predictedResult == 0) site="SUSPICIOUS";
        else if(predictedResult == -1) site="PHISHING";

        UserTest.setText("The URL Seems to be "+site);
    }

    private int DeterMineResult(int[] knnIndex, int lastIndex) {
        int predictedResult;
        int plus=0,zero=0,minus=0;

        for(int z=0;z<K;z++){
            int temp = data.get(knnIndex[z]).get(lastIndex);
            if (temp == 1) plus++;
            else if (temp == 0) zero++;
            else if (temp == -1) minus++;
            else System.out.println(".........  Warning 1 .........");
        }

        if(plus>minus){
            if(plus>zero) predictedResult = 1;
            else predictedResult = 0;
        }
        else {
            if(minus>zero) predictedResult = -1;
            else predictedResult = 0;
        }
        return predictedResult;
    }
}