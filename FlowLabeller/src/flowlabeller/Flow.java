/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package flowlabeller;

/**
 *
 * @author baskoro
 */
public class Flow {

    public Flow() {
        this.start = 0;
        this.end = 0;
    }
    
    /**
     * @return the start
     */
    public int getStart() {
        return start;
    }

    /**
     * @param start the start to set
     */
    public void setStart(int start) {
        this.start = start;
    }

    /**
     * @return the end
     */
    public int getEnd() {
        return end;
    }

    /**
     * @param end the end to set
     */
    public void setEnd(int end) {
        this.end = end;
    }

    /**
     * @return the exploitName
     */
    public String getExploitName() {
        return exploitName;
    }

    /**
     * @param exploitName the exploitName to set
     */
    public void setExploitName(String exploitName) {
        this.exploitName = exploitName;
    }

    /**
     * @return the flowFilename
     */
    public String getFlowFilename() {
        return flowFilename;
    }

    /**
     * @param flowFilename the flowFilename to set
     */
    public void setFlowFilename(String flowFilename) {
        this.flowFilename = flowFilename;
    }

    /**
     * @return the directory
     */
    public String getDirectory() {
        return directory;
    }

    /**
     * @param directory the directory to set
     */
    public void setDirectory(String directory) {
        this.directory = directory;
    }

    /**
     * @return the payloadName
     */
    public String getPayloadName() {
        return payloadName;
    }

    /**
     * @param payloadName the payloadName to set
     */
    public void setPayloadName(String payloadName) {
        this.payloadName = payloadName;
    }

    /**
     * @return the encoderName
     */
    public String getEncoderName() {
        return encoderName;
    }

    /**
     * @param encoderName the encoderName to set
     */
    public void setEncoderName(String encoderName) {
        this.encoderName = encoderName;
    }

    /**
     * @return the payloadType
     */
    public String getPayloadType() {
        return payloadType;
    }

    /**
     * @param payloadType the payloadType to set
     */
    public void setPayloadType(String payloadType) {
        this.payloadType = payloadType;
    }
    
    /**
     * @return the flowAbsoluteFilename
     */
    public String getFlowAbsoluteFilename() {
        return flowAbsoluteFilename;
    }

    /**
     * @param flowAbsoluteFilename the flowAbsoluteFilename to set
     */
    public void setFlowAbsoluteFilename(String flowAbsoluteFilename) {
        this.flowAbsoluteFilename = flowAbsoluteFilename;
    }
    
    private String flowFilename;
    private String flowAbsoluteFilename;
    private String directory;
    private String payloadName;
    private String encoderName;
    private String payloadType;
    private String exploitName;
    private int start,end;
}
