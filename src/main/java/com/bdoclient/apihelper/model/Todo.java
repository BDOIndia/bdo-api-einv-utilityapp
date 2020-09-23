package com.bdoclient.apihelper.model;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.validation.constraints.NotNull;

@ApiModel("Todo Entity description here")
public class Todo {
    
    @NotNull
    @ApiModelProperty(notes = "${todo.id}", example = "1", required = true, position = 0)
    private Long id;
    
    @NotNull
    @ApiModelProperty(notes = "${todo.task}", example = "Learn more Spring Boot", required = true, position = 1)
    private String task;
   
    @ApiModelProperty(notes = "${todo.description}", example = "Code Code Code", required = false, position = 2)
    private String description;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTask() {
        return task;
    }

    public void setTask(String task) {
        this.task = task;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}