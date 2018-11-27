/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package flowlabeller;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;

/**
 *
 * @author baskoro
 */
public class FlowDataset {

    /**
     * @return the currentIndex
     */
    public int getCurrentIndex() {
        return currentIndex;
    }

    /**
     * @param currentIndex the currentIndex to set
     */
    public void setCurrentIndex(int currentIndex) {
        this.currentIndex = currentIndex+1;
    }

    /**
     * @return the numOfLabelledThisSession
     */
    public int getNumOfLabelledThisSession() {
        return numOfLabelledThisSession;
    }

    /**
     * @return the numOfLabelledTotal
     */
    public int getNumOfLabelledTotal() {
        return numOfLabelledTotal;
    }
    private TreeMap<String, Flow> dataset;
    private ArrayList<String> keys;
    private int currentIndex;
    private String rootdir;
    private int numOfLabelledThisSession, numOfLabelledTotal;
    
    public FlowDataset(String rootdir) throws FileNotFoundException, IOException {
        this.rootdir = rootdir;
        this.dataset = new TreeMap<String, Flow>();
        this.numOfLabelledThisSession = 0;
        this.numOfLabelledTotal = 0;
        this.load();
    }
    
    public void load() throws FileNotFoundException, IOException {
        //load from csv
        File fMainDir = new File(this.rootdir + "/msfScripts/");
        File[] osDirs = fMainDir.listFiles();
        
        for(File osDir : osDirs) {
            if(osDir.isDirectory()) {
                try {
                    this.readCsv(osDir);
                }
                catch(FileNotFoundException ex) {
                    continue;
                }
            }
        }
        
        this.setCurrentIndex(-1);
        //load from existing data, if any
        try {
            this.readExisting();
        }
        catch(FileNotFoundException ex) {
            
        }
        
        this.keys = new ArrayList<>(this.dataset.keySet());
        
        
    }
    
    private void readCsv(File osDir) throws FileNotFoundException, IOException {
        BufferedReader brCsv;
        brCsv = new BufferedReader(new InputStreamReader(new FileInputStream(osDir.getAbsolutePath() + "/exploits_payloads_encoders.csv")));
        
        String line;
        while((line = brCsv.readLine()) != null) {
            String[] columns = line.split(",");
            String dirname = columns[0];
            String[] tmp = dirname.split("_");
            File flowDir = new File(this.rootdir + "/Flows/Pcap/" + osDir.getName() + "/" + tmp[0] + "/" + dirname + ".pcap");
            if(!flowDir.exists()) {
                continue;
            }
            else {
                File[] flowFiles = flowDir.listFiles();
                for(File flowFile : flowFiles) {
                    if(!flowFile.getName().startsWith("192.168.066.006")){
                        continue;
                    }
                    else {
                        Flow flow = new Flow();
                        String key = osDir.getName() + "/" + tmp[0] + "/" + dirname + ".pcap/" + flowFile.getName();
                        flow.setFlowAbsoluteFilename(flowFile.getAbsolutePath());
                        flow.setFlowFilename(flowFile.getName());
                        flow.setDirectory(osDir.getName() + "/"  + dirname);
                        flow.setExploitName(columns[1]);
                        flow.setPayloadName(columns[2]);
                        flow.setEncoderName(columns[3]);
                        flow.setPayloadType(columns[4]);
                        
                        this.dataset.put(key, flow);
                    }
                }
            }
        }
    }
    
    private void readExisting() throws IOException {
        String filename = this.rootdir + "/Flows/labelled.csv";
        BufferedReader brLabelledSet = new BufferedReader(new InputStreamReader(new FileInputStream(filename)));
        
        String line;
        while((line = brLabelledSet.readLine()) != null) {
            String[] columns = line.split(",");
            String key = columns[0];
            Flow flow = this.get(key);
            flow.setStart(Integer.parseInt(columns[5]));
            flow.setEnd(Integer.parseInt(columns[6]));
            this.numOfLabelledTotal++;
        }
        
        brLabelledSet.close();
        
        filename = this.rootdir + "/Flows/last_accessed_index.txt";
        BufferedReader brIndex = new BufferedReader(new InputStreamReader(new FileInputStream(filename)));
        this.currentIndex = Integer.parseInt(brIndex.readLine());
        brIndex.close();
    }
    
    public void saveDataset() throws FileNotFoundException, IOException {
        String filename = this.rootdir + "/Flows/labelled.csv";
        BufferedWriter bwLabelledSet = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        
        this.numOfLabelledTotal = 0;
        
        for(String key : this.dataset.keySet()) {
            Flow flow = this.dataset.get(key);
            
            //hasn't been labelled
            if(flow.getStart() == 0 && flow.getEnd() == 0) {
                continue;
            }
            else {
                this.numOfLabelledTotal++;
                String data = key + "," + flow.getExploitName() + "," + flow.getPayloadName() + "," + flow.getEncoderName() + "," + flow.getPayloadType() + "," + flow.getStart() + "," + flow.getEnd() + "\n";
                bwLabelledSet.write(data);
                bwLabelledSet.flush();
            }
        }
        
        bwLabelledSet.close();
        
        filename = this.rootdir + "/Flows/last_accessed_index.txt";
        BufferedWriter bwIndex = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        
        bwIndex.write((this.currentIndex-1) + "");
        bwIndex.close();
    }
    
    public void update(String key, int start, int end, String payload_type) {
        Flow flow = this.dataset.get(key);
        if(flow.getStart() == flow.getEnd() || (flow.getStart() != start && flow.getEnd() != end)) {
            this.numOfLabelledThisSession++;
        }
        flow.setStart(start);
        flow.setEnd(end);
        flow.setPayloadType(payload_type);
    }
    
    public void updateCurrent(int start, int end, String payload_type) {
        Flow flow = this.get(this.currentIndex-1);
        if(flow.getStart() == flow.getEnd() || (flow.getStart() != start && flow.getEnd() != end)) {
            this.numOfLabelledThisSession++;
        }
        flow.setStart(start);
        flow.setEnd(end);
        flow.setPayloadType(payload_type);
    }
    
    public Flow get(String key) {
        return this.dataset.get(key);
    }
    
    public Flow get(int index) {
        String key = this.keys.get(index);
        return this.dataset.get(key);
    }
    
    public Flow nextFlowFile() {
        if(this.getCurrentIndex() >= this.dataset.size()) {
            this.setCurrentIndex(this.dataset.size() - 1);
            Flow flow = this.get(this.getCurrentIndex());
            return flow;
        }
        else {
            Flow flow = this.get(this.getCurrentIndex());
            this.currentIndex++;
            return flow;
        }
    }
    
    public Flow prevFlowFile() {
        if(this.getCurrentIndex() < 0) {
            this.setCurrentIndex(0);
            Flow flow = this.get(this.getCurrentIndex());
            return flow;
        }
        else {
            Flow flow = this.get(this.getCurrentIndex());
            this.currentIndex--;
            return flow;
        }
    }
}
