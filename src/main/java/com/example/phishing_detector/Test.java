package com.example.phishing_detector;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Scanner;

public class Test {
    public static void main(String[] args) {
        ArrayList<ArrayList<Integer>> data = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(new File("src/Data/PhishingData.arff")));
            String line;
            while ((line = br.readLine())!=null){
                if(line.equals("")) continue;
                else if(line.charAt(0) == '@') continue;
                String[] arr = line.split(",");
                ArrayList<Integer> temp = new ArrayList<>();
                for (String s : arr) {
                    temp.add(Integer.parseInt(s));
                }
                data.add(temp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        int index;
        Scanner sc = new Scanner(System.in);
        while ((index = sc.nextInt())!=-1){
            System.out.println(data.get(index));
        }

    }
}
