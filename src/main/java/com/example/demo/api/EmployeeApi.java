package com.example.demo.api;

import com.example.demo.dao.entity.Employee;
import com.example.demo.manager.EmployeeManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/employees")
public class EmployeeApi {

    private EmployeeManager employeeManager;

    @Autowired
    public EmployeeApi(EmployeeManager employeeManager) {

        this.employeeManager = employeeManager;
    }

    @GetMapping("/all")
    public Iterable<Employee> getAll() {

        return employeeManager.findAllEmployees();
    }

    @GetMapping
    public Optional<Employee> getById(@RequestParam Long index) {

        return employeeManager.findEmployeeById(index);
    }


    @GetMapping("/allByDeptName")
    public Iterable<Employee> getAllEmployeesFromDepartment(@RequestParam(name = "departmentName") String departmentName) {

        return employeeManager.findAllEmployeesInDepartment(departmentName);
    }

    @GetMapping("/allByDeptIdAndEmployeeName")
    public Iterable<Employee> getAllEmployeesByDeptIdAndEmplName(@RequestParam(name = "departmentId") Long departmentId,
                                                                  @RequestParam(name = "employeeLastName") String employeeLastName) {

        return employeeManager.findAllEmployeesByDeptIdAndEmplName(departmentId, employeeLastName);
    }

    @PostMapping
    public ResponseEntity<Employee> addEmployee(@RequestBody Employee employee) {
        Employee emp = employeeManager.saveEmployee(employee);
        return  new ResponseEntity<>(emp, HttpStatus.OK);
    }

    @DeleteMapping
    public ResponseEntity<String> deleteEmployee(@RequestParam(name = "employeeId") Long employeeId) {
        employeeManager.deleteEmployeeById(employeeId);
        return new ResponseEntity<>("Employee with ID:" + employeeId + " deleted successfully", HttpStatus.OK);
    }

    @PutMapping
    public ResponseEntity<Employee> updateEmployee(@RequestBody Employee employee) {
        Employee emp = employeeManager.saveEmployee(employee);
        return  new ResponseEntity<>(emp, HttpStatus.OK);
    }

}
