"""
Enterprise Orchestration Engine

Provides comprehensive workflow orchestration, automation, and task management
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
from contextlib import asynccontextmanager
import structlog
from concurrent.futures import ThreadPoolExecutor
import yaml

logger = structlog.get_logger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


class TriggerType(Enum):
    """Workflow trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    WEBHOOK = "webhook"
    METRIC_THRESHOLD = "metric_threshold"
    API_CALL = "api_call"


class ActionType(Enum):
    """Workflow action types"""
    VM_OPERATION = "vm_operation"
    CLUSTER_OPERATION = "cluster_operation"
    STORAGE_OPERATION = "storage_operation"
    NETWORK_OPERATION = "network_operation"
    NOTIFICATION = "notification"
    SCRIPT_EXECUTION = "script_execution"
    API_CALL = "api_call"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    PARALLEL = "parallel"


@dataclass
class WorkflowTask:
    """Workflow task definition"""
    id: str
    name: str
    action_type: ActionType
    parameters: Dict[str, Any]
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    
    # Execution settings
    timeout: int = 300  # 5 minutes
    retry_count: int = 3
    retry_delay: int = 30
    
    # Conditional execution
    condition: Optional[str] = None
    
    # Status tracking
    status: TaskStatus = TaskStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowTrigger:
    """Workflow trigger definition"""
    id: str
    trigger_type: TriggerType
    configuration: Dict[str, Any]
    enabled: bool = True
    
    # Schedule configuration (for scheduled triggers)
    schedule: Optional[str] = None  # Cron expression
    
    # Event configuration (for event-driven triggers)
    event_filters: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metric threshold configuration
    metric_name: Optional[str] = None
    threshold_value: Optional[float] = None
    threshold_operator: Optional[str] = None  # >, <, >=, <=, ==
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """Workflow definition"""
    id: str
    name: str
    description: str
    version: str = "1.0.0"
    
    # Tasks and dependencies
    tasks: List[WorkflowTask] = field(default_factory=list)
    
    # Triggers
    triggers: List[WorkflowTrigger] = field(default_factory=list)
    
    # Execution settings
    max_concurrent_tasks: int = 10
    timeout: int = 3600  # 1 hour
    
    # Status tracking
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Execution history
    executions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    tenant_id: Optional[str] = None
    created_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    id: str
    workflow_id: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    
    # Execution context
    input_parameters: Dict[str, Any] = field(default_factory=dict)
    output_results: Dict[str, Any] = field(default_factory=dict)
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Task execution tracking
    task_executions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Error handling
    error_message: Optional[str] = None
    failed_task_id: Optional[str] = None
    
    # Metadata
    triggered_by: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class OrchestrationEngine:
    """Enterprise orchestration engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        
        # Workflow storage
        self.workflows: Dict[str, Workflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        
        # Execution management
        self.running_executions: Set[str] = set()
        self.execution_semaphore = asyncio.Semaphore(
            config.get("max_concurrent_executions", 50)
        )
        
        # Task executors
        self.task_executors: Dict[ActionType, Callable] = {}
        self._init_task_executors()
        
        # Scheduler
        self.scheduler_enabled = config.get("scheduler_enabled", True)
        self.scheduler_task: Optional[asyncio.Task] = None
        
        # Thread pool for CPU-intensive tasks
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get("thread_pool_size", 10)
        )
        
        logger.info("Orchestration engine initialized", 
                   enabled=self.enabled,
                   scheduler_enabled=self.scheduler_enabled)
    
    def _init_task_executors(self):
        """Initialize task executors"""
        self.task_executors = {
            ActionType.VM_OPERATION: self._execute_vm_operation,
            ActionType.CLUSTER_OPERATION: self._execute_cluster_operation,
            ActionType.STORAGE_OPERATION: self._execute_storage_operation,
            ActionType.NETWORK_OPERATION: self._execute_network_operation,
            ActionType.NOTIFICATION: self._execute_notification,
            ActionType.SCRIPT_EXECUTION: self._execute_script,
            ActionType.API_CALL: self._execute_api_call,
            ActionType.CONDITIONAL: self._execute_conditional,
            ActionType.LOOP: self._execute_loop,
            ActionType.PARALLEL: self._execute_parallel
        }
    
    async def start(self):
        """Start orchestration engine"""
        if not self.enabled:
            return
        
        # Start scheduler
        if self.scheduler_enabled:
            self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        logger.info("Orchestration engine started")
    
    async def stop(self):
        """Stop orchestration engine"""
        # Stop scheduler
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Wait for running executions to complete
        if self.running_executions:
            logger.info("Waiting for running executions to complete", 
                       count=len(self.running_executions))
            
            # Give executions time to complete gracefully
            await asyncio.sleep(30)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("Orchestration engine stopped")
    
    async def create_workflow(self, workflow_data: Dict[str, Any]) -> Workflow:
        """Create new workflow"""
        workflow_id = workflow_data.get("id") or str(uuid.uuid4())
        
        if workflow_id in self.workflows:
            raise ValueError(f"Workflow {workflow_id} already exists")
        
        # Create workflow tasks
        tasks = []
        for task_data in workflow_data.get("tasks", []):
            task = WorkflowTask(
                id=task_data["id"],
                name=task_data["name"],
                action_type=ActionType(task_data["action_type"]),
                parameters=task_data.get("parameters", {}),
                depends_on=task_data.get("depends_on", []),
                timeout=task_data.get("timeout", 300),
                retry_count=task_data.get("retry_count", 3),
                retry_delay=task_data.get("retry_delay", 30),
                condition=task_data.get("condition"),
                metadata=task_data.get("metadata", {})
            )
            tasks.append(task)
        
        # Create workflow triggers
        triggers = []
        for trigger_data in workflow_data.get("triggers", []):
            trigger = WorkflowTrigger(
                id=trigger_data["id"],
                trigger_type=TriggerType(trigger_data["trigger_type"]),
                configuration=trigger_data.get("configuration", {}),
                enabled=trigger_data.get("enabled", True),
                schedule=trigger_data.get("schedule"),
                event_filters=trigger_data.get("event_filters", []),
                metric_name=trigger_data.get("metric_name"),
                threshold_value=trigger_data.get("threshold_value"),
                threshold_operator=trigger_data.get("threshold_operator"),
                metadata=trigger_data.get("metadata", {})
            )
            triggers.append(trigger)
        
        # Create workflow
        workflow = Workflow(
            id=workflow_id,
            name=workflow_data["name"],
            description=workflow_data.get("description", ""),
            version=workflow_data.get("version", "1.0.0"),
            tasks=tasks,
            triggers=triggers,
            max_concurrent_tasks=workflow_data.get("max_concurrent_tasks", 10),
            timeout=workflow_data.get("timeout", 3600),
            tenant_id=workflow_data.get("tenant_id"),
            created_by=workflow_data.get("created_by"),
            tags=workflow_data.get("tags", []),
            metadata=workflow_data.get("metadata", {})
        )
        
        # Validate workflow
        await self._validate_workflow(workflow)
        
        self.workflows[workflow_id] = workflow
        
        logger.info("Workflow created", 
                   workflow_id=workflow_id,
                   name=workflow.name,
                   tasks=len(workflow.tasks))
        
        return workflow
    
    async def _validate_workflow(self, workflow: Workflow):
        """Validate workflow definition"""
        task_ids = {task.id for task in workflow.tasks}
        
        # Check for duplicate task IDs
        if len(task_ids) != len(workflow.tasks):
            raise ValueError("Duplicate task IDs found in workflow")
        
        # Check dependencies
        for task in workflow.tasks:
            for dep_id in task.depends_on:
                if dep_id not in task_ids:
                    raise ValueError(f"Task {task.id} depends on non-existent task {dep_id}")
        
        # Check for circular dependencies
        await self._check_circular_dependencies(workflow.tasks)
    
    async def _check_circular_dependencies(self, tasks: List[WorkflowTask]):
        """Check for circular dependencies in workflow"""
        # Build dependency graph
        graph = {task.id: task.depends_on for task in tasks}
        
        # Use DFS to detect cycles
        visited = set()
        rec_stack = set()
        
        def has_cycle(node):
            if node in rec_stack:
                return True
            if node in visited:
                return False
            
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in graph.get(node, []):
                if has_cycle(neighbor):
                    return True
            
            rec_stack.remove(node)
            return False
        
        for task_id in graph:
            if task_id not in visited:
                if has_cycle(task_id):
                    raise ValueError("Circular dependency detected in workflow")
    
    async def execute_workflow(self, workflow_id: str, 
                              input_parameters: Optional[Dict[str, Any]] = None,
                              triggered_by: Optional[str] = None) -> WorkflowExecution:
        """Execute workflow"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        # Create execution instance
        execution = WorkflowExecution(
            id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            input_parameters=input_parameters or {},
            triggered_by=triggered_by,
            tenant_id=workflow.tenant_id
        )
        
        self.executions[execution.id] = execution
        
        # Execute workflow asynchronously
        asyncio.create_task(self._execute_workflow_async(execution))
        
        logger.info("Workflow execution started", 
                   execution_id=execution.id,
                   workflow_id=workflow_id)
        
        return execution
    
    async def _execute_workflow_async(self, execution: WorkflowExecution):
        """Execute workflow asynchronously"""
        async with self.execution_semaphore:
            self.running_executions.add(execution.id)
            
            try:
                execution.status = WorkflowStatus.RUNNING
                execution.started_at = datetime.utcnow()
                
                workflow = self.workflows[execution.workflow_id]
                
                # Execute tasks in dependency order
                await self._execute_workflow_tasks(workflow, execution)
                
                execution.status = WorkflowStatus.COMPLETED
                execution.completed_at = datetime.utcnow()
                
                logger.info("Workflow execution completed", 
                           execution_id=execution.id)
                
            except Exception as e:
                execution.status = WorkflowStatus.FAILED
                execution.completed_at = datetime.utcnow()
                execution.error_message = str(e)
                
                logger.error("Workflow execution failed", 
                           execution_id=execution.id,
                           error=str(e))
            
            finally:
                self.running_executions.discard(execution.id)
    
    async def _execute_workflow_tasks(self, workflow: Workflow, execution: WorkflowExecution):
        """Execute workflow tasks in dependency order"""
        # Build execution plan
        execution_plan = await self._build_execution_plan(workflow.tasks)
        
        # Execute tasks in batches
        for batch in execution_plan:
            # Execute tasks in parallel within batch
            batch_tasks = []
            
            for task_id in batch:
                task = next(t for t in workflow.tasks if t.id == task_id)
                batch_tasks.append(
                    self._execute_task(task, execution, workflow)
                )
            
            # Wait for batch completion
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Check for failures
            for i, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    task_id = batch[i]
                    execution.failed_task_id = task_id
                    raise result
    
    async def _build_execution_plan(self, tasks: List[WorkflowTask]) -> List[List[str]]:
        """Build task execution plan based on dependencies"""
        # Topological sort to determine execution order
        in_degree = {task.id: len(task.depends_on) for task in tasks}
        queue = [task.id for task in tasks if in_degree[task.id] == 0]
        execution_plan = []
        
        while queue:
            # Current batch (tasks with no remaining dependencies)
            current_batch = list(queue)
            execution_plan.append(current_batch)
            queue.clear()
            
            # Update in-degrees for next batch
            for task_id in current_batch:
                task = next(t for t in tasks if t.id == task_id)
                
                # Find tasks that depend on this task
                for other_task in tasks:
                    if task_id in other_task.depends_on:
                        in_degree[other_task.id] -= 1
                        if in_degree[other_task.id] == 0:
                            queue.append(other_task.id)
        
        return execution_plan
    
    async def _execute_task(self, task: WorkflowTask, execution: WorkflowExecution, 
                           workflow: Workflow):
        """Execute individual task"""
        task_execution = {
            "task_id": task.id,
            "status": TaskStatus.RUNNING,
            "started_at": datetime.utcnow(),
            "attempts": 0
        }
        
        execution.task_executions[task.id] = task_execution
        
        # Check condition if specified
        if task.condition:
            if not await self._evaluate_condition(task.condition, execution):
                task_execution["status"] = TaskStatus.SKIPPED
                task_execution["completed_at"] = datetime.utcnow()
                return
        
        # Execute task with retries
        for attempt in range(task.retry_count + 1):
            try:
                task_execution["attempts"] = attempt + 1
                
                # Get task executor
                executor = self.task_executors.get(task.action_type)
                if not executor:
                    raise ValueError(f"No executor for action type {task.action_type}")
                
                # Execute task with timeout
                result = await asyncio.wait_for(
                    executor(task, execution, workflow),
                    timeout=task.timeout
                )
                
                # Task completed successfully
                task_execution["status"] = TaskStatus.COMPLETED
                task_execution["completed_at"] = datetime.utcnow()
                task_execution["result"] = result
                
                logger.info("Task completed", 
                           task_id=task.id,
                           execution_id=execution.id,
                           attempts=attempt + 1)
                
                return result
                
            except Exception as e:
                task_execution["error"] = str(e)
                
                if attempt < task.retry_count:
                    task_execution["status"] = TaskStatus.RETRYING
                    logger.warning("Task failed, retrying", 
                                 task_id=task.id,
                                 attempt=attempt + 1,
                                 error=str(e))
                    
                    await asyncio.sleep(task.retry_delay)
                else:
                    task_execution["status"] = TaskStatus.FAILED
                    task_execution["completed_at"] = datetime.utcnow()
                    
                    logger.error("Task failed after all retries", 
                               task_id=task.id,
                               execution_id=execution.id,
                               error=str(e))
                    
                    raise
    
    async def _evaluate_condition(self, condition: str, execution: WorkflowExecution) -> bool:
        """Evaluate task condition"""
        # Simple condition evaluation (can be extended)
        # Example: "input.cpu_usage > 80"
        
        try:
            # Create evaluation context
            context = {
                "input": execution.input_parameters,
                "output": execution.output_results,
                "tasks": {
                    task_id: task_exec.get("result", {})
                    for task_id, task_exec in execution.task_executions.items()
                }
            }
            
            # Evaluate condition using safe expression evaluator
            # Using simple comparison operators only for security
            try:
                # Parse simple conditions like "status == 'completed'"
                if "==" in condition:
                    left, right = condition.split("==", 1)
                    left_val = context.get(left.strip())
                    right_val = right.strip().strip("'\"")
                    return left_val == right_val
                elif "!=" in condition:
                    left, right = condition.split("!=", 1)
                    left_val = context.get(left.strip())
                    right_val = right.strip().strip("'\"")
                    return left_val != right_val
                else:
                    # Default to True for unknown conditions
                    return True
            except Exception:
                return True
            
        except Exception as e:
            logger.error("Condition evaluation failed", 
                        condition=condition, error=str(e))
            return False
    
    # Task executors
    async def _execute_vm_operation(self, task: WorkflowTask, execution: WorkflowExecution, 
                                   workflow: Workflow) -> Dict[str, Any]:
        """Execute VM operation task"""
        operation = task.parameters.get("operation")
        vm_name = task.parameters.get("vm_name")
        
        logger.info("Executing VM operation", 
                   operation=operation, vm_name=vm_name)
        
        # Simulate VM operation
        await asyncio.sleep(1)
        
        return {
            "operation": operation,
            "vm_name": vm_name,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _execute_cluster_operation(self, task: WorkflowTask, execution: WorkflowExecution, 
                                        workflow: Workflow) -> Dict[str, Any]:
        """Execute cluster operation task"""
        operation = task.parameters.get("operation")
        cluster_name = task.parameters.get("cluster_name")
        
        logger.info("Executing cluster operation", 
                   operation=operation, cluster_name=cluster_name)
        
        # Simulate cluster operation
        await asyncio.sleep(2)
        
        return {
            "operation": operation,
            "cluster_name": cluster_name,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _execute_storage_operation(self, task: WorkflowTask, execution: WorkflowExecution, 
                                        workflow: Workflow) -> Dict[str, Any]:
        """Execute storage operation task"""
        operation = task.parameters.get("operation")
        datastore_name = task.parameters.get("datastore_name")
        
        logger.info("Executing storage operation", 
                   operation=operation, datastore_name=datastore_name)
        
        # Simulate storage operation
        await asyncio.sleep(1.5)
        
        return {
            "operation": operation,
            "datastore_name": datastore_name,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _execute_network_operation(self, task: WorkflowTask, execution: WorkflowExecution, 
                                        workflow: Workflow) -> Dict[str, Any]:
        """Execute network operation task"""
        operation = task.parameters.get("operation")
        network_name = task.parameters.get("network_name")
        
        logger.info("Executing network operation", 
                   operation=operation, network_name=network_name)
        
        # Simulate network operation
        await asyncio.sleep(1)
        
        return {
            "operation": operation,
            "network_name": network_name,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _execute_notification(self, task: WorkflowTask, execution: WorkflowExecution, 
                                   workflow: Workflow) -> Dict[str, Any]:
        """Execute notification task"""
        message = task.parameters.get("message")
        recipients = task.parameters.get("recipients", [])
        
        logger.info("Sending notification", 
                   message=message, recipients=recipients)
        
        # Simulate notification
        await asyncio.sleep(0.5)
        
        return {
            "message": message,
            "recipients": recipients,
            "sent_at": datetime.utcnow().isoformat()
        }
    
    async def _execute_script(self, task: WorkflowTask, execution: WorkflowExecution, 
                             workflow: Workflow) -> Dict[str, Any]:
        """Execute script task"""
        script_content = task.parameters.get("script")
        script_type = task.parameters.get("type", "python")
        
        logger.info("Executing script", script_type=script_type)
        
        # Execute script in thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.thread_pool,
            self._run_script,
            script_content,
            script_type
        )
        
        return result
    
    def _run_script(self, script_content: str, script_type: str) -> Dict[str, Any]:
        """Run script in thread pool"""
        # Simplified script execution
        # In production, use proper sandboxing
        
        if script_type == "python":
            # Execute Python script safely (restricted environment)
            # For security, only allow basic operations
            logger.warning("Python script execution is disabled for security reasons")
            return {"result": "Python script execution disabled for security", "error": "Security restriction"}
        
        return {"result": "Script type not supported"}
    
    async def _execute_api_call(self, task: WorkflowTask, execution: WorkflowExecution, 
                               workflow: Workflow) -> Dict[str, Any]:
        """Execute API call task"""
        url = task.parameters.get("url")
        method = task.parameters.get("method", "GET")
        headers = task.parameters.get("headers", {})
        data = task.parameters.get("data")
        
        logger.info("Executing API call", url=url, method=method)
        
        # Simulate API call
        await asyncio.sleep(1)
        
        return {
            "url": url,
            "method": method,
            "status_code": 200,
            "response": {"message": "API call successful"},
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _execute_conditional(self, task: WorkflowTask, execution: WorkflowExecution, 
                                  workflow: Workflow) -> Dict[str, Any]:
        """Execute conditional task"""
        condition = task.parameters.get("condition")
        true_action = task.parameters.get("true_action")
        false_action = task.parameters.get("false_action")
        
        # Evaluate condition
        condition_result = await self._evaluate_condition(condition, execution)
        
        # Execute appropriate action
        action = true_action if condition_result else false_action
        
        if action:
            # Create sub-task for the action
            sub_task = WorkflowTask(
                id=f"{task.id}_sub",
                name=f"{task.name} - Sub Action",
                action_type=ActionType(action["type"]),
                parameters=action.get("parameters", {})
            )
            
            return await self._execute_task(sub_task, execution, workflow)
        
        return {"condition_result": condition_result, "action_executed": action is not None}
    
    async def _execute_loop(self, task: WorkflowTask, execution: WorkflowExecution, 
                           workflow: Workflow) -> Dict[str, Any]:
        """Execute loop task"""
        items = task.parameters.get("items", [])
        action = task.parameters.get("action")
        
        results = []
        
        for i, item in enumerate(items):
            # Create sub-task for each iteration
            sub_task = WorkflowTask(
                id=f"{task.id}_loop_{i}",
                name=f"{task.name} - Loop {i}",
                action_type=ActionType(action["type"]),
                parameters={**action.get("parameters", {}), "item": item}
            )
            
            result = await self._execute_task(sub_task, execution, workflow)
            results.append(result)
        
        return {"loop_results": results, "iterations": len(items)}
    
    async def _execute_parallel(self, task: WorkflowTask, execution: WorkflowExecution, 
                               workflow: Workflow) -> Dict[str, Any]:
        """Execute parallel task"""
        actions = task.parameters.get("actions", [])
        
        # Create sub-tasks for parallel execution
        sub_tasks = []
        for i, action in enumerate(actions):
            sub_task = WorkflowTask(
                id=f"{task.id}_parallel_{i}",
                name=f"{task.name} - Parallel {i}",
                action_type=ActionType(action["type"]),
                parameters=action.get("parameters", {})
            )
            sub_tasks.append(self._execute_task(sub_task, execution, workflow))
        
        # Execute all sub-tasks in parallel
        results = await asyncio.gather(*sub_tasks, return_exceptions=True)
        
        return {"parallel_results": results, "task_count": len(actions)}
    
    async def _scheduler_loop(self):
        """Scheduler loop for scheduled workflows"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._check_scheduled_workflows()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scheduler loop failed", error=str(e))
    
    async def _check_scheduled_workflows(self):
        """Check for scheduled workflows that need to be executed"""
        current_time = datetime.utcnow()
        
        for workflow in self.workflows.values():
            for trigger in workflow.triggers:
                if (trigger.trigger_type == TriggerType.SCHEDULED and 
                    trigger.enabled and trigger.schedule):
                    
                    # Check if workflow should be triggered
                    # This is a simplified check - in production, use proper cron parsing
                    if await self._should_trigger_scheduled_workflow(trigger, current_time):
                        await self.execute_workflow(
                            workflow.id,
                            triggered_by=f"scheduler:{trigger.id}"
                        )
    
    async def _should_trigger_scheduled_workflow(self, trigger: WorkflowTrigger, 
                                               current_time: datetime) -> bool:
        """Check if scheduled workflow should be triggered"""
        # Simplified schedule checking
        # In production, use proper cron expression parsing
        return False
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return None
        
        return {
            "id": workflow.id,
            "name": workflow.name,
            "status": workflow.status.value,
            "created_at": workflow.created_at.isoformat(),
            "updated_at": workflow.updated_at.isoformat(),
            "tasks_count": len(workflow.tasks),
            "triggers_count": len(workflow.triggers),
            "executions_count": len(workflow.executions)
        }
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status"""
        execution = self.executions.get(execution_id)
        if not execution:
            return None
        
        return {
            "id": execution.id,
            "workflow_id": execution.workflow_id,
            "status": execution.status.value,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "task_executions": execution.task_executions,
            "error_message": execution.error_message
        }


class WorkflowManager:
    """Workflow management interface"""
    
    def __init__(self, orchestration_engine: OrchestrationEngine):
        self.engine = orchestration_engine
        logger.info("Workflow manager initialized")
    
    async def import_workflow_from_yaml(self, yaml_content: str) -> Workflow:
        """Import workflow from YAML definition"""
        try:
            workflow_data = yaml.safe_load(yaml_content)
            return await self.engine.create_workflow(workflow_data)
        except Exception as e:
            logger.error("Failed to import workflow from YAML", error=str(e))
            raise
    
    async def export_workflow_to_yaml(self, workflow_id: str) -> str:
        """Export workflow to YAML format"""
        workflow = self.engine.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        # Convert workflow to dictionary
        workflow_dict = {
            "id": workflow.id,
            "name": workflow.name,
            "description": workflow.description,
            "version": workflow.version,
            "tasks": [
                {
                    "id": task.id,
                    "name": task.name,
                    "action_type": task.action_type.value,
                    "parameters": task.parameters,
                    "depends_on": task.depends_on,
                    "timeout": task.timeout,
                    "retry_count": task.retry_count,
                    "retry_delay": task.retry_delay,
                    "condition": task.condition,
                    "metadata": task.metadata
                }
                for task in workflow.tasks
            ],
            "triggers": [
                {
                    "id": trigger.id,
                    "trigger_type": trigger.trigger_type.value,
                    "configuration": trigger.configuration,
                    "enabled": trigger.enabled,
                    "schedule": trigger.schedule,
                    "event_filters": trigger.event_filters,
                    "metric_name": trigger.metric_name,
                    "threshold_value": trigger.threshold_value,
                    "threshold_operator": trigger.threshold_operator,
                    "metadata": trigger.metadata
                }
                for trigger in workflow.triggers
            ],
            "max_concurrent_tasks": workflow.max_concurrent_tasks,
            "timeout": workflow.timeout,
            "tenant_id": workflow.tenant_id,
            "tags": workflow.tags,
            "metadata": workflow.metadata
        }
        
        return yaml.dump(workflow_dict, default_flow_style=False)
    
    async def clone_workflow(self, workflow_id: str, new_name: str) -> Workflow:
        """Clone existing workflow"""
        original_workflow = self.engine.workflows.get(workflow_id)
        if not original_workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        # Export and modify
        yaml_content = await self.export_workflow_to_yaml(workflow_id)
        workflow_data = yaml.safe_load(yaml_content)
        
        # Update for clone
        workflow_data["id"] = str(uuid.uuid4())
        workflow_data["name"] = new_name
        workflow_data["version"] = "1.0.0"
        
        return await self.engine.create_workflow(workflow_data)
    
    def list_workflows(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List workflows"""
        workflows = []
        
        for workflow in self.engine.workflows.values():
            if tenant_id and workflow.tenant_id != tenant_id:
                continue
            
            workflows.append({
                "id": workflow.id,
                "name": workflow.name,
                "description": workflow.description,
                "version": workflow.version,
                "status": workflow.status.value,
                "tasks_count": len(workflow.tasks),
                "triggers_count": len(workflow.triggers),
                "created_at": workflow.created_at.isoformat(),
                "tags": workflow.tags
            })
        
        return workflows
    
    def list_executions(self, workflow_id: Optional[str] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """List workflow executions"""
        executions = []
        
        for execution in self.engine.executions.values():
            if workflow_id and execution.workflow_id != workflow_id:
                continue
            
            executions.append({
                "id": execution.id,
                "workflow_id": execution.workflow_id,
                "status": execution.status.value,
                "started_at": execution.started_at.isoformat() if execution.started_at else None,
                "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
                "triggered_by": execution.triggered_by
            })
        
        # Sort by start time (most recent first)
        executions.sort(
            key=lambda x: x["started_at"] or "1970-01-01T00:00:00",
            reverse=True
        )
        
        return executions[:limit]
