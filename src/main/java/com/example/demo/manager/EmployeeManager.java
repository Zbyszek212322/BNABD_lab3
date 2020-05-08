package com.example.demo.manager;

import com.example.demo.dao.DepartmentRepository;
import com.example.demo.dao.EmployeeRepository;
import com.example.demo.dao.entity.Department;
import com.example.demo.dao.entity.Employee;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class EmployeeManager {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;

    @Autowired
    public EmployeeManager(EmployeeRepository employeeRepository, DepartmentRepository departmentRepository) {
        super();
        this.employeeRepository = employeeRepository;
        this.departmentRepository = departmentRepository;
    }

    public Optional<Employee> findEmployeeById(Long id) {

        return employeeRepository.findById(id);
    }

    public Iterable<Employee> findAllEmployees() {

        return employeeRepository.findAll();
    }

    public Iterable<Employee> findAllEmployeesInDepartment(String departmentName) {

        Iterable<Employee> employeesInDepartment = employeeRepository.findByDepartment(departmentRepository.findByDepartmentName(departmentName));
        return employeesInDepartment;
    }

    public Iterable<Employee> findAllEmployeesByDeptIdAndEmplName(Long deptId, String employeeLastName) {

        Department dept = departmentRepository.findFirstById(deptId);
        Iterable<Employee> employeesInDepartment = employeeRepository.findByLastNameAndDepartment(employeeLastName, dept);

        return employeesInDepartment;
    }

    public Employee saveEmployee(Employee employee) {

        return employeeRepository.save(employee);
    }

    public void deleteEmployeeById(Long id) {

        employeeRepository.deleteById(id);
    }
}
