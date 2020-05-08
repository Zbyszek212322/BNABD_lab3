package com.example.demo.api;

import com.example.demo.dao.entity.Department;
import com.example.demo.manager.DepartmentManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/departments")
public class DepartmentApi {

    private DepartmentManager departmentManager;

    @Autowired
    public DepartmentApi(DepartmentManager departmentManager) {

        this.departmentManager = departmentManager;
    }

    @GetMapping("/all")
    public Iterable<Department> getAll() {

        return departmentManager.findAllDepartments();
    }

    @GetMapping
    public Optional<Department> getById(@RequestParam Long index) {

        return departmentManager.findDepartmentById(index);
    }

    @PostMapping
    public ResponseEntity<Department> addDepartment(@RequestBody Department department) {
        Department dept = departmentManager.saveDepartment(department);
        return  new ResponseEntity<>(dept, HttpStatus.OK);
    }

    @DeleteMapping
    public ResponseEntity<String> deleteDepartment(@RequestParam(name = "departmentId") Long departmentId) {
        departmentManager.deleteDepartmentById(departmentId);
        return new ResponseEntity<>("Department with ID:" + departmentId + " deleted successfully", HttpStatus.OK);
    }

    @PutMapping
    public ResponseEntity<Department> updateDepartment(@RequestBody Department department) {
        Department dept = departmentManager.saveDepartment(department);
        return  new ResponseEntity<>(dept, HttpStatus.OK);
    }

}
